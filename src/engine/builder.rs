//! On-demand BuildKit with state owned by a persistent machine, not a client registration.
use super::EngineConfig;
use crate::embedded::{control, handle::VmHandle};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::net::{UnixListener, UnixStream};

const IMAGE: &str = "docker.io/moby/buildkit:buildx-stable-1";
const GUEST_SOCKET: &str = "/run/buildkit/buildkitd.sock";
const LABEL: &str = "smolvm.engine.builder";
const IDLE: Duration = Duration::from_secs(10);

/// The builder has its own OS-owned socket; its adapter only exists while used.
pub fn config(engine: &EngineConfig) -> EngineConfig {
    EngineConfig {
        socket: engine.socket.with_extension("buildkit.sock"),
        root: engine.root.join("buildkit"),
    }
}

fn machine_name(config: &EngineConfig) -> String {
    let hash = hex::encode(Sha256::digest(config.root.as_os_str().as_encoded_bytes()));
    format!("buildkit-{}", &hash[..16])
}

fn boot(config: &EngineConfig) -> crate::Result<VmHandle> {
    let db = crate::db::SmolvmDb::open()?;
    let name = machine_name(config);
    let bridge = config.root.join("guest.sock");
    if db.get_vm(&name)?.is_none() {
        control::create_vm_from_spec(
            &db,
            &name,
            Some(IMAGE),
            crate::machine_spec::CreateSpec {
                labels: [(LABEL.into(), config.root.to_string_lossy().into_owned())].into(),
                net: true,
                network_backend: Some(crate::network::NetworkBackend::VirtioNet),
                entrypoint: Some(vec!["buildkitd".into()]),
                cmd: Some(vec![
                    "--allow-insecure-entitlement=network.host".into(),
                    "--addr".into(),
                    format!("unix://{GUEST_SOCKET}"),
                    "--root".into(),
                    "/workspace/buildkit".into(),
                ]),
                published_sockets: vec![crate::config::PublishedSocketConfig {
                    direction: smolvm_protocol::publish_socket::SocketDirection::Expose,
                    guest_path: GUEST_SOCKET.into(),
                    host_path: Some(bridge.to_string_lossy().into_owned()),
                    baud: None,
                }],
                ..Default::default()
            },
        )?;
    }
    let record = control::get_record(&db, &name)?;
    if record.labels.get(LABEL).map(String::as_str) != Some(config.root.to_string_lossy().as_ref())
    {
        return Err(crate::Error::config(
            "BuildKit",
            "the builder machine name is owned by another machine",
        ));
    }
    let mut started = control::start_vm(&db, &name)?;
    let ready = (|| -> crate::Result<()> {
        if started.freshly_started {
            started.handle.launch_image_workload(&name, &record)?;
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            let mut probe = crate::agent::RunConfig::new(
                IMAGE,
                vec!["buildctl".into(), "debug".into(), "workers".into()],
            )
            .in_machine(&record, &name, &[]);
            probe.timeout = Some(Duration::from_secs(5));
            let result = started.handle.run_config(probe)?;
            if result.0 == 0 {
                break;
            }
            if std::time::Instant::now() >= deadline {
                return Err(crate::Error::config(
                    "BuildKit",
                    String::from_utf8_lossy(&result.2),
                ));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Ok(())
    })();
    if let Err(error) = ready {
        let _ = started.handle.stop();
        return Err(error);
    }
    Ok(started.handle)
}

/// Serve BuildKit's native protocol, stopping the VM after its last client leaves.
/// Builder registrations can be deleted/recreated without deleting the machine's disk.
pub async fn serve(config: EngineConfig) -> crate::Result<()> {
    std::fs::create_dir_all(&config.root)?;
    let _lock = super::supervisor::lock(config.root.join("owner.lock")).await?;
    let activated = super::supervisor::activated_listener()?;
    let os_owned = activated.is_some();
    let listener = match activated {
        Some(listener) => listener,
        None => super::bind_socket(&config.socket)?,
    };
    let result = serve_listener(&config, listener).await;
    if !os_owned {
        let _ = std::fs::remove_file(&config.socket);
    }
    result
}

async fn serve_listener(config: &EngineConfig, listener: UnixListener) -> crate::Result<()> {
    let mut tasks = tokio::task::JoinSet::new();
    let mut machine = None;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let result = async {
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (mut client, _) = accepted?;
                    if machine.is_none() {
                        let config = config.clone();
                        machine = Some(tokio::task::spawn_blocking(move || boot(&config))
                            .await.map_err(|e| crate::Error::config("BuildKit", e.to_string()))??);
                    }
                    let mut upstream = UnixStream::connect(config.root.join("guest.sock")).await?;
                    tasks.spawn(async move {
                        if let Err(error) = tokio::io::copy_bidirectional(&mut client, &mut upstream).await {
                            tracing::debug!(%error, "BuildKit client disconnected");
                        }
                    });
                }
                _ = tasks.join_next(), if !tasks.is_empty() => {}
                _ = tokio::time::sleep(IDLE), if tasks.is_empty() => break,
                _ = terminate.recv() => break,
                _ = interrupt.recv() => break,
            }
        }
        Ok(())
    }.await;
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    if let Some(mut handle) = machine {
        tokio::task::spawn_blocking(move || handle.stop())
            .await
            .map_err(|e| crate::Error::config("stop BuildKit", e.to_string()))??;
    }
    result
}
