//! One demand-owned watcher per adapter, with one agent connection per VM.
//! Container aliases sharing a VM never multiply guest connection/thread use.
use super::super::Engine;
use std::{
    collections::BTreeMap, io, os::unix::fs::MetadataExt, path::PathBuf, sync::Arc, time::Duration,
};
use tokio::{
    io::AsyncReadExt,
    sync::watch,
    task::{AbortHandle, JoinSet},
};

pub(crate) struct Watch {
    updates: watch::Receiver<u64>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Watch {
    fn drop(&mut self) {
        self.task.abort();
    }
}
pub(crate) struct Subscription {
    _owner: Arc<Watch>,
    updates: watch::Receiver<u64>,
}
impl Subscription {
    pub(crate) async fn changed(&mut self) -> io::Result<()> {
        self.updates
            .changed()
            .await
            .map_err(|_| io::Error::other("Guest listener watch closed"))
    }
}
pub(crate) fn subscribe(engine: &Arc<Engine>) -> io::Result<Subscription> {
    let mut shared = engine.app_listener_watch.lock();
    let owner = match shared.upgrade() {
        Some(owner) => owner,
        None => {
            let events = engine.events.subscribe()?;
            let (send, updates) = watch::channel(0);
            let engine = engine.clone();
            let task = tokio::spawn(async move {
                run(engine, events, send).await;
            });
            let owner = Arc::new(Watch { updates, task });
            *shared = Arc::downgrade(&owner);
            owner
        }
    };
    let updates = owner.updates.clone();
    Ok(Subscription {
        _owner: owner,
        updates,
    })
}

// A replaced socket at the same path is a different VM observation source.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Vm {
    socket: PathBuf,
    device: u64,
    inode: u64,
    changed: (i64, i64),
}
fn inventory(engine: &Engine) -> io::Result<Vec<Vm>> {
    engine.refresh_containers().map_err(io::Error::other)?;
    let containers = engine.containers.read();
    if containers.len() > 512 {
        return Err(io::Error::other(
            "Too many containers for app listener observation",
        ));
    }
    let mut vms = std::collections::BTreeSet::new();
    for container in containers.values() {
        let record = container.record();
        if record.state.status != "running" {
            continue;
        }
        if let Some(socket) = record.agent_socket {
            let metadata = match std::fs::metadata(&socket) {
                Ok(metadata) => metadata,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };
            vms.insert(Vm {
                socket,
                device: metadata.dev(),
                inode: metadata.ino(),
                changed: (metadata.ctime(), metadata.ctime_nsec()),
            });
        }
    }
    Ok(vms.into_iter().collect())
}
fn notify(send: &watch::Sender<u64>) {
    send.send_modify(|sequence| *sequence = sequence.wrapping_add(1));
}
async fn observe(vm: Vm, send: watch::Sender<u64>) {
    let mut backoff = Duration::from_secs(1);
    let mut disconnected = false;
    loop {
        let connected = tokio::time::timeout(
            Duration::from_secs(6),
            super::super::runtime::listener_watch(&vm.socket),
        )
        .await;
        let result: io::Result<()> = match connected {
            Ok(Ok(mut stream)) => {
                backoff = Duration::from_secs(1);
                disconnected = false;
                loop {
                    let mut generation = [0; 8];
                    match stream.read_exact(&mut generation).await {
                        Ok(_) => notify(&send),
                        Err(error) => break Err(error),
                    }
                }
            }
            Ok(Err(error)) => Err(error),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Guest listener watch timed out",
            )),
        };
        if !disconnected {
            notify(&send);
            disconnected = true;
        }
        if result.is_err_and(|e| e.kind() == io::ErrorKind::Unsupported) {
            // Discovery marks this guest unavailable; keep observing other VMs.
            // Restart/recreation changes its socket identity and retries it.
            std::future::pending::<()>().await;
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

async fn run(
    engine: Arc<Engine>,
    mut events: super::super::events::Subscription,
    send: watch::Sender<u64>,
) {
    let mut tasks = JoinSet::new();
    let mut active: BTreeMap<Vm, AbortHandle> = BTreeMap::new();
    loop {
        let vms = match inventory(&engine) {
            Ok(vms) => vms,
            Err(error) => {
                tracing::warn!(%error,"Cannot observe app listeners");
                return;
            }
        };
        active.retain(|vm, task| {
            if vms.contains(vm) {
                true
            } else {
                task.abort();
                false
            }
        });
        for vm in vms {
            active
                .entry(vm.clone())
                .or_insert_with(|| tasks.spawn(observe(vm, send.clone())));
        }
        loop {
            tokio::select! {
                event=events.changed()=>{
                    if event.is_err(){return;}
                    break;
                },
                _=send.closed()=>return,
                result=tasks.join_next(), if !tasks.is_empty()=>{
                    if !matches!(result, Some(Err(ref error)) if error.is_cancelled()) {
                        // Close the stream so clients resubscribe instead of
                        // silently retaining a dead observer in the VM map.
                        tracing::warn!(?result, "App listener observer exited unexpectedly");
                        return;
                    }
                },
            }
        }
    }
}
