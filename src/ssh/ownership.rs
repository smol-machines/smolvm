//! Temporary ownership handoff for VM processes spawned by an SSH startup.
//! No listener or task remains after the startup request completes.
use anyhow::{ensure, Context, Result};
use std::{
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixStream as BlockingStream},
    path::PathBuf,
    sync::{
        atomic::{AtomicI32, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixListener,
};

pub(crate) const SOCKET_ENV: &str = "SMOLVM_SSH_STARTUP_SOCKET";
pub(crate) const MACHINE_ENV: &str = "SMOLVM_SSH_STARTUP_MACHINE";

pub(crate) fn managed() -> bool {
    std::env::var_os(SOCKET_ENV).is_some()
}

/// Called before the VMM opens resources or drops its host credentials.
/// Until acknowledgement it stays in the launching request's process group.
pub(crate) fn register_boot() -> Result<()> {
    let Some(path) = std::env::var_os(SOCKET_ENV) else {
        return Ok(());
    };
    let machine = std::env::var(MACHINE_ENV).context("missing startup machine identity")?;
    ensure!(machine.len() <= 256, "invalid startup machine identity");
    let mut stream = BlockingStream::connect(PathBuf::from(path))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(&(machine.len() as u16).to_be_bytes())?;
    stream.write_all(machine.as_bytes())?;
    let mut ack = [0];
    stream.read_exact(&mut ack)?;
    ensure!(ack == [1], "startup ownership was refused");
    // Only detach from group cancellation once the proxy owns our exact PID.
    if unsafe { libc::setpgid(0, 0) } != 0 {
        return Err(std::io::Error::last_os_error()).context("detach registered boot process");
    }
    std::env::remove_var(SOCKET_ENV);
    std::env::remove_var(MACHINE_ENV);
    Ok(())
}

#[derive(Clone)]
struct Vm {
    machine: String,
    pid: i32,
    started: u64,
}

pub(super) struct Owner {
    directory: tempfile::TempDir,
    group: Arc<AtomicI32>,
    vms: Arc<Mutex<Vec<Vm>>>,
    listener: tokio::task::JoinHandle<()>,
}
impl Owner {
    pub fn new(machine: &str) -> Result<Self> {
        let directory = tempfile::Builder::new().prefix("smol-ssh-").tempdir()?;
        let socket = directory.path().join("s");
        let listener = UnixListener::bind(&socket)?;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
        let group = Arc::new(AtomicI32::new(0));
        let vms = Arc::new(Mutex::new(Vec::new()));
        let expected = machine.to_owned();
        let peers = vms.clone();
        let expected_group = group.clone();
        let listener = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let register = async {
                    let peer = stream.peer_cred()?;
                    let pid = peer.pid().context("startup peer PID unavailable")?;
                    ensure!(
                        peer.uid() == unsafe { libc::geteuid() },
                        "unexpected startup user"
                    );
                    let group = expected_group.load(Ordering::SeqCst);
                    ensure!(
                        group > 0 && unsafe { libc::getpgid(pid) } == group,
                        "startup peer is outside the owned process group"
                    );
                    let started = crate::process::process_start_time(pid)
                        .context("startup process identity unavailable")?;
                    let length = stream.read_u16().await? as usize;
                    ensure!(
                        length > 0 && length <= 256,
                        "invalid startup identity length"
                    );
                    let mut bytes = vec![0; length];
                    stream.read_exact(&mut bytes).await?;
                    let machine = String::from_utf8(bytes)?;
                    ensure!(
                        machine == expected
                            || machine.starts_with(crate::image_seed::SEED_MACHINE_PREFIX),
                        "unexpected startup machine"
                    );
                    {
                        let mut peers = peers
                            .lock()
                            .map_err(|_| anyhow::anyhow!("startup ownership lock poisoned"))?;
                        ensure!(peers.len() < 32, "too many startup processes");
                        peers.push(Vm {
                            machine,
                            pid,
                            started,
                        });
                    }
                    stream.write_all(&[1]).await?;
                    Ok::<_, anyhow::Error>(())
                };
                let _ = tokio::time::timeout(Duration::from_secs(5), register).await;
            }
        });
        Ok(Self {
            directory,
            group,
            vms,
            listener,
        })
    }

    pub fn configure(&self, command: &mut tokio::process::Command) {
        command.env(SOCKET_ENV, self.directory.path().join("s"));
    }

    pub fn spawned(&self, pid: u32) {
        self.group.store(pid as i32, Ordering::SeqCst);
    }

    pub async fn finish(&mut self, canceled: bool, target: &str) -> Result<()> {
        self.listener.abort();
        let _ = (&mut self.listener).await;
        if !canceled {
            return Ok(());
        }
        let vms = self
            .vms
            .lock()
            .map_err(|_| anyhow::anyhow!("startup ownership lock poisoned"))?
            .clone();
        for vm in vms {
            if !crate::process::is_our_process_strict(vm.pid, Some(vm.started)) {
                continue;
            }
            // The startup child has exited, so it cannot commit after this read.
            // A resumed VM with durable Running metadata already owns execution;
            // closing the editor must not kill it in the final detach window.
            let committed = if vm.machine == target {
                crate::db::SmolvmDb::open()?
                    .get_vm(&vm.machine)?
                    .is_some_and(|record| {
                        record.state == crate::config::RecordState::Running
                            && record.paused_checkpoint.is_none()
                            && record.pid == Some(vm.pid)
                            && record.pid_start_time == Some(vm.started)
                    })
            } else {
                false
            };
            if !committed {
                ensure!(
                    crate::process::kill_verified(vm.pid, Some(vm.started))
                        || !crate::process::is_our_process_strict(vm.pid, Some(vm.started)),
                    "could not stop canceled boot process"
                );
                tokio::time::timeout(Duration::from_secs(3), async {
                    while crate::process::is_our_process_strict(vm.pid, Some(vm.started)) {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                })
                .await
                .context("canceled boot process did not exit")?;
            }
        }
        Ok(())
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        self.listener.abort();
    }
}
