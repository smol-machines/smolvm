//! Own a pending start request while keeping the SSH client's input cancellable.
use anyhow::{Context, Result};
use std::{io::Cursor, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, Chain},
    process::{Child, Command},
};

const START_TIMEOUT: Duration = Duration::from_secs(300);
#[cfg(unix)]
const CANCEL_GRACE: Duration = Duration::from_secs(3);
// A client can send its identification before we start the server. Never let
// an unauthenticated stream grow without bound while an image is provisioning.
const MAX_EARLY_INPUT: usize = 64 * 1024;

pub(super) struct Interrupts {
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
    #[cfg(unix)]
    hangup: tokio::signal::unix::Signal,
}
impl Interrupts {
    pub fn new() -> Result<Self> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            Ok(Self {
                interrupt: signal(SignalKind::interrupt())?,
                terminate: signal(SignalKind::terminate())?,
                hangup: signal(SignalKind::hangup())?,
            })
        }
        #[cfg(not(unix))]
        Ok(Self {})
    }

    pub async fn wait(&mut self) {
        #[cfg(unix)]
        tokio::select! {
            _ = self.interrupt.recv() => {},
            _ = self.terminate.recv() => {},
            _ = self.hangup.recv() => {},
        }
        #[cfg(not(unix))]
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn running(record: &crate::config::VmRecord) -> bool {
    record.paused_checkpoint.is_none()
        && record.state == crate::config::RecordState::Running
        && record.is_process_alive()
}

async fn read_early<R: AsyncRead + Unpin>(input: &mut R, buffered: &mut Vec<u8>) -> Result<()> {
    let mut chunk = [0; 4096];
    let count = input
        .read(&mut chunk)
        .await
        .context("read SSH client during machine startup")?;
    anyhow::ensure!(count > 0, "SSH client disconnected during machine startup");
    anyhow::ensure!(
        buffered.len() + count <= MAX_EARLY_INPUT,
        "SSH client sent too much input before machine startup"
    );
    buffered.extend_from_slice(&chunk[..count]);
    Ok(())
}

#[cfg(not(unix))]
async fn acquire(file: &std::fs::File) -> Result<()> {
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(()),
            Err(std::fs::TryLockError::WouldBlock) => {
                tokio::time::sleep(Duration::from_millis(25)).await
            }
            Err(std::fs::TryLockError::Error(error)) => {
                return Err(error).context("lock SSH machine startup")
            }
        }
    }
}

#[cfg(unix)]
async fn operation_locks(
    machine: &str,
) -> Result<(
    crate::agent::fork::ForkSourceLock,
    crate::agent::fork::ForkSourceLock,
)> {
    let saved = loop {
        if let Some(lock) = crate::agent::fork::try_lock_saved_execution(machine)? {
            break lock;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    let source = loop {
        if let Some(lock) = crate::agent::fork::try_lock_fork_source(machine)? {
            break lock;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    Ok((saved, source))
}

pub(super) async fn prepare<R: AsyncRead + Unpin>(
    machine: &str,
    input: R,
    interrupts: &mut Interrupts,
) -> Result<Chain<Cursor<Vec<u8>>, R>> {
    #[cfg(unix)]
    {
        // Keep warm connections in this process, but never bypass another
        // client's initialization merely because it has published Running.
        if let Some(_saved) = crate::agent::fork::try_lock_saved_execution(machine)? {
            if let Some(_source) = crate::agent::fork::try_lock_fork_source(machine)? {
                let record = crate::db::SmolvmDb::open()?
                    .get_vm(machine)?
                    .context("selected machine does not exist")?;
                if running(&record) {
                    return Ok(Cursor::new(Vec::new()).chain(input));
                }
            }
        }
        let mut command = Command::new(std::env::current_exe()?);
        command.args(["machine", "ssh-start", "--name", machine]);
        supervised_start(command, input, interrupts).await
    }
    #[cfg(not(unix))]
    prepare_owned(machine, input, interrupts).await
}

/// The pipe writer belongs only to the SSH proxy. Even SIGKILL closes it,
/// letting the startup owner cancel and release its locks after cleanup.
/// This helper exists only while starting or waiting for a machine.
#[cfg(unix)]
async fn supervised_start<R: AsyncRead + Unpin>(
    mut command: Command,
    mut input: R,
    interrupts: &mut Interrupts,
) -> Result<Chain<Cursor<Vec<u8>>, R>> {
    use std::os::unix::process::CommandExt;
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    // A client's process-group termination must not prevent cleanup. No
    // kill-on-drop: closing the pipe asks the owner to finish that cleanup.
    command.as_std_mut().process_group(0);
    let mut child = command.spawn()?;
    let lifetime = child
        .stdin
        .take()
        .context("missing startup lifetime pipe")?;
    let mut buffered = Vec::new();
    let deadline = tokio::time::sleep(START_TIMEOUT);
    tokio::pin!(deadline);
    let result = loop {
        tokio::select! {
            status = child.wait() => break status.context("wait for SSH startup owner"),
            read = read_early(&mut input, &mut buffered) => if let Err(error) = read { break Err(error); },
            _ = interrupts.wait() => break Err(anyhow::anyhow!("SSH machine startup canceled")),
            _ = &mut deadline => break Err(anyhow::anyhow!("SSH machine startup timed out")),
        }
    };
    drop(lifetime);
    match result {
        Ok(status) => anyhow::ensure!(
            status.success(),
            "could not start the selected machine for SSH"
        ),
        Err(error) => {
            // The owner independently has the same bounded startup deadline.
            // If cleanup is slow, leave it holding the operation locks rather
            // than kill it and allow another start to race its unfinished VM.
            tokio::time::timeout(CANCEL_GRACE * 2 + Duration::from_secs(2), child.wait())
                .await
                .context("SSH startup cleanup is still in progress")?
                .context("wait for canceled SSH startup owner")?;
            return Err(error);
        }
    }
    Ok(Cursor::new(buffered).chain(input))
}

pub(super) async fn prepare_owned<R: AsyncRead + Unpin>(
    machine: &str,
    mut input: R,
    interrupts: &mut Interrupts,
) -> Result<Chain<Cursor<Vec<u8>>, R>> {
    let read_record = || {
        crate::db::SmolvmDb::open()?
            .get_vm(machine)?
            .ok_or_else(|| anyhow::anyhow!("selected machine does not exist"))
    };
    // New AgentManagers always start disconnected. Use the saved process
    // identity, then let the SSH capability probe verify agent reachability.
    let deadline = tokio::time::Instant::now() + START_TIMEOUT;
    #[cfg(not(unix))]
    let lock = super::identity::startup_lock(machine)?;
    let mut buffered = Vec::new();
    let locks = {
        #[cfg(unix)]
        let locked = operation_locks(machine);
        #[cfg(not(unix))]
        let locked = acquire(&lock);
        tokio::pin!(locked);
        loop {
            tokio::select! {
                result = &mut locked => break result?,
                read = read_early(&mut input, &mut buffered) => read?,
                _ = interrupts.wait() => anyhow::bail!("SSH machine startup canceled"),
                _ = tokio::time::sleep_until(deadline) => anyhow::bail!("SSH machine startup timed out"),
            }
        }
    };
    // Another connection may have completed startup while we waited.
    let record = read_record()?;
    if running(&record) {
        return Ok(Cursor::new(buffered).chain(input));
    }
    let action = if record.paused_checkpoint.is_some() {
        "resume"
    } else {
        "start"
    };
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args(["machine", action, "--name", machine])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    #[cfg(unix)]
    crate::agent::fork::inherit_operation_locks(command.as_std_mut(), &[&locks.0, &locks.1])?;
    #[cfg(not(unix))]
    let _ = locks;
    // Keep the locks until wait_start has cleaned up every unfinished boot.
    wait_start(
        command,
        input,
        interrupts,
        deadline.saturating_duration_since(tokio::time::Instant::now()),
        machine,
        buffered,
    )
    .await
}

async fn wait_start<R: AsyncRead + Unpin>(
    mut command: Command,
    mut input: R,
    interrupts: &mut Interrupts,
    timeout: Duration,
    machine: &str,
    mut buffered: Vec<u8>,
) -> Result<Chain<Cursor<Vec<u8>>, R>> {
    #[cfg(unix)]
    let mut owner = super::ownership::Owner::new(machine)?;
    #[cfg(unix)]
    owner.configure(&mut command);
    #[cfg(not(unix))]
    let _ = machine;
    // Helpers remain in this group; VMs leave it only after registration.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.as_std_mut().process_group(0);
    }
    let mut child = command.kill_on_drop(true).spawn()?;
    #[cfg(unix)]
    owner.spawned(child.id().context("missing SSH startup child PID")?);
    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);
    let result = loop {
        tokio::select! {
            status = wait_start_exit(&mut child) => break status,
            read = read_early(&mut input, &mut buffered) => if let Err(error) = read { break Err(error); },
            _ = interrupts.wait() => break Err(anyhow::anyhow!("SSH machine startup canceled")),
            _ = &mut deadline => break Err(anyhow::anyhow!("SSH machine startup timed out")),
        }
    };
    if let Err(error) = result {
        let canceled = cancel(&mut child)
            .await
            .context("cancel SSH machine startup");
        #[cfg(unix)]
        owner
            .finish(true, machine)
            .await
            .context("clean up canceled SSH boot")?;
        canceled?;
        return Err(error);
    }
    #[cfg(unix)]
    owner.finish(false, machine).await?;
    Ok(Cursor::new(buffered).chain(input))
}

// Observe without reaping: the child pins its process-group ID until all
// attached helpers have been signaled. A reaped PID could be reused by an
// unrelated process group before cancellation reaches it.
#[cfg(unix)]
async fn exited_unreaped(pid: u32) -> Result<()> {
    loop {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                pid,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error).context("observe SSH startup child");
            }
        } else if unsafe { info.si_pid() } != 0 {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn wait_start_exit(child: &mut Child) -> Result<()> {
    #[cfg(unix)]
    {
        let pid = child.id().context("missing SSH startup child PID")?;
        exited_unreaped(pid).await?;
        // A successful start has detached registered VMs. Any other descendants
        // still in this group are unfinished helpers owned by this request.
        unsafe { libc::kill(-(pid as i32), libc::SIGKILL) };
    }
    let status = child.wait().await.context("wait for SSH machine startup")?;
    anyhow::ensure!(
        status.success(),
        "could not start the selected machine for SSH"
    );
    Ok(())
}

async fn cancel(child: &mut Child) -> Result<()> {
    let Some(pid) = child.id() else {
        return Ok(());
    };
    #[cfg(unix)]
    {
        // The unreaped child pins its PID/group against reuse. SIGINT gives the
        // existing seed builder and VM startup guards a chance to clean up.
        unsafe { libc::kill(-(pid as i32), libc::SIGINT) };
        let _ = tokio::time::timeout(CANCEL_GRACE, exited_unreaped(pid)).await;
        unsafe { libc::kill(-(pid as i32), libc::SIGKILL) };
    }
    #[cfg(not(unix))]
    let _ = pid;
    child.kill().await.context("reap canceled startup child")?;
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    fn command(script: &str) -> Command {
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", script])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    }

    #[tokio::test]
    async fn supervised_start_preserves_client_bytes() {
        let (mut client, input) = tokio::io::duplex(128);
        client.write_all(b"SSH-2.0-supervised\r\n").await.unwrap();
        let mut input =
            supervised_start(command("sleep 0.1"), input, &mut Interrupts::new().unwrap())
                .await
                .unwrap();
        client.write_all(b"\0\x01\xfflater").await.unwrap();
        drop(client);
        let mut bytes = Vec::new();
        input.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"SSH-2.0-supervised\r\n\0\x01\xfflater");
    }

    #[tokio::test]
    async fn supervised_disconnect_waits_for_cleanup() {
        let directory = tempfile::tempdir().unwrap();
        let finished = directory.path().join("finished");
        let mut owner = command("read ignored; sleep 0.1; touch \"$1\"");
        owner.arg("startup-owner").arg(&finished);
        let (client, input) = tokio::io::duplex(128);
        drop(client);
        let result = tokio::time::timeout(
            Duration::from_secs(3),
            supervised_start(owner, input, &mut Interrupts::new().unwrap()),
        )
        .await
        .unwrap();
        assert!(result.err().unwrap().to_string().contains("disconnected"));
        assert!(finished.exists(), "returned before the owner cleaned up");
    }

    #[tokio::test]
    async fn dropping_supervised_request_keeps_cleanup_owner_alive() {
        let directory = tempfile::tempdir().unwrap();
        let ready = directory.path().join("ready");
        let finished = directory.path().join("finished");
        let mut owner = command("touch \"$1\"; read ignored; sleep 0.1; touch \"$2\"");
        owner.arg("startup-owner").arg(&ready).arg(&finished);
        let (_client, input) = tokio::io::duplex(128);
        let pending = tokio::spawn(async move {
            supervised_start(owner, input, &mut Interrupts::new().unwrap()).await
        });
        tokio::time::timeout(Duration::from_secs(3), async {
            while !ready.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        pending.abort();
        assert!(pending.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(3), async {
            while !finished.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("aborting the request killed its cleanup owner");
    }

    #[tokio::test]
    async fn startup_preserves_buffered_and_later_client_bytes() {
        let (mut client, input) = tokio::io::duplex(128);
        client.write_all(b"SSH-2.0-owned\r\n").await.unwrap();
        let mut input = wait_start(
            command("sleep 0.1"),
            input,
            &mut Interrupts::new().unwrap(),
            Duration::from_secs(2),
            "startup-test",
            Vec::new(),
        )
        .await
        .unwrap();
        client.write_all(b"\0\x01\xfflater").await.unwrap();
        drop(client);
        let mut bytes = Vec::new();
        input.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"SSH-2.0-owned\r\n\0\x01\xfflater");
    }

    #[tokio::test]
    async fn disconnected_client_cancels_pending_start() {
        let (client, input) = tokio::io::duplex(128);
        drop(client);
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            wait_start(
                command("sleep 30"),
                input,
                &mut Interrupts::new().unwrap(),
                Duration::from_secs(30),
                "startup-test",
                Vec::new(),
            ),
        )
        .await
        .unwrap();
        assert!(result.err().unwrap().to_string().contains("disconnected"));
    }

    #[tokio::test]
    async fn stalled_start_has_a_deadline() {
        let (_client, input) = tokio::io::duplex(128);
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            wait_start(
                command("sleep 30"),
                input,
                &mut Interrupts::new().unwrap(),
                Duration::from_millis(100),
                "startup-test",
                Vec::new(),
            ),
        )
        .await
        .unwrap();
        assert!(result.err().unwrap().to_string().contains("timed out"));
    }

    #[tokio::test]
    async fn failed_start_does_not_enter_the_ssh_protocol() {
        let (_client, input) = tokio::io::duplex(128);
        let result = wait_start(
            command("exit 7"),
            input,
            &mut Interrupts::new().unwrap(),
            Duration::from_secs(2),
            "startup-test",
            Vec::new(),
        )
        .await;
        assert!(result
            .err()
            .unwrap()
            .to_string()
            .contains("could not start"));
    }

    #[tokio::test]
    async fn excessive_pre_handshake_input_cancels_start() {
        let (mut client, input) = tokio::io::duplex(MAX_EARLY_INPUT + 1);
        client
            .write_all(&vec![0; MAX_EARLY_INPUT + 1])
            .await
            .unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            wait_start(
                command("sleep 30"),
                input,
                &mut Interrupts::new().unwrap(),
                Duration::from_secs(30),
                "startup-test",
                Vec::new(),
            ),
        )
        .await
        .unwrap();
        assert!(result.err().unwrap().to_string().contains("too much input"));
    }

    #[tokio::test]
    async fn unresponsive_start_is_killed_and_reaped_after_grace() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pid");
        let mut command = command("trap '' INT; echo $$ > \"$1\"; exec sleep 30");
        command.arg("owned-startup-test").arg(&path);
        let (_client, input) = tokio::io::duplex(128);
        let result = tokio::time::timeout(
            Duration::from_secs(6),
            wait_start(
                command,
                input,
                &mut Interrupts::new().unwrap(),
                Duration::from_millis(200),
                "startup-test",
                Vec::new(),
            ),
        )
        .await
        .unwrap();
        assert!(result.err().unwrap().to_string().contains("timed out"));
        let pid: i32 = std::fs::read_to_string(path)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
    }
}
