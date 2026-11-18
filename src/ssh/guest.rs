//! Bridge SSH channels to the actual agent; callbacks never wait on guest I/O.
use crate::agent::{
    interactive_control::{Action, Builtin, Request, Session, Terminal},
    interactive_input, AgentClient, AgentManager, InteractiveInput, InteractiveOutput,
};
use russh::{server, ChannelId, ChannelWriteHalf};
use std::{
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::{mpsc, oneshot};

struct ActiveThread(Arc<AtomicUsize>);
impl ActiveThread {
    fn new(count: Arc<AtomicUsize>) -> Self {
        count.fetch_add(1, Ordering::SeqCst);
        Self(count)
    }
}
impl Drop for ActiveThread {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(super) enum Operation {
    Sftp,
    Execute {
        command: String,
        terminal: Option<Terminal>,
        env: Vec<(String, String)>,
    },
    Tcp {
        host: String,
        port: u16,
        reply: server::ChannelOpenHandle,
    },
}

#[allow(clippy::too_many_arguments)]
pub(super) fn start(
    id: ChannelId,
    mut receiver: mpsc::UnboundedReceiver<Option<Vec<u8>>>,
    writer: ChannelWriteHalf<server::Msg>,
    queued: Arc<AtomicUsize>,
    handle: server::Handle,
    machine: String,
    expected_host: Arc<russh::keys::PublicKey>,
    operation: Operation,
    active: Arc<AtomicUsize>,
) -> (tokio::task::JoinHandle<()>, mpsc::Sender<Action>) {
    let (controls, mut requests) = mpsc::channel::<Action>(16);
    let task = tokio::spawn(async move {
        let (command, terminal, env, builtin, reply) = match operation {
            Operation::Sftp => (Vec::new(), None, Vec::new(), Some(Builtin::Sftp), None),
            Operation::Execute {
                command,
                terminal,
                env,
            } => (
                vec!["sh".into(), "-c".into(), command],
                terminal,
                env,
                None,
                None,
            ),
            Operation::Tcp { host, port, reply } => (
                Vec::new(),
                None,
                Vec::new(),
                Some(Builtin::TcpConnect { host, port }),
                Some(reply),
            ),
        };
        let forwarding = reply.is_some();
        let capability = builtin.as_ref().map(Builtin::capability);
        let accepted = Arc::new(AtomicBool::new(false));
        let Ok((input, input_rx)) = interactive_input(8) else {
            if let Some(reply) = reply {
                reply
                    .reject(russh::ChannelOpenFailure::ResourceShortage)
                    .await;
            } else {
                let _ = writer.exit_status(255).await;
                let _ = writer.close().await;
            }
            return;
        };
        let writer = Arc::new(writer);
        let (output, mut output_rx) = mpsc::channel(8);
        let (finished, done) = oneshot::channel();
        let (started, ready) = oneshot::channel();
        let session_id = format!("{:032x}", rand::random::<u128>());
        let control_machine = machine.clone();
        let control_id = session_id.clone();
        let count = ActiveThread::new(active.clone());
        let spawned = std::thread::Builder::new()
            .name("ssh-guest".into())
            .spawn(move || {
                let _active = count;
                let value = (|| -> anyhow::Result<i32> {
                    super::identity::verify(&machine, &expected_host)?;
                    let record = crate::db::SmolvmDb::open()?
                        .get_vm(&machine)?
                        .ok_or_else(|| anyhow::anyhow!("selected machine no longer exists"))?;
                    let target = crate::workload::machine_target(&record);
                    // Builtins need the workload's namespaces and identity,
                    // but never dereference its host secrets or credential store.
                    let mut environment = if capability.is_some() { record.env.clone() } else { crate::secrets::record_env_with_secrets(&record)? };
                    for (key, value) in env {
                        environment.retain(|(existing, _)| existing != &key);
                        environment.push((key, value));
                    }
                    let manager = AgentManager::for_vm(&machine)?;
                    let mut client = AgentClient::connect(manager.vsock_socket())?;
                    if let Some(capability) = capability {
                        anyhow::ensure!(client.supports_capability(capability)?, "this running machine needs an updated runtime for this SSH operation");
                    }
                    Ok(client.vm_exec_controlled_io(
                        Session {
                            id: session_id,
                            command,
                            builtin,
                            env: environment,
                            workdir: record.workdir,
                            timeout_ms: None,
                            terminal,
                            target: Some(target),
                            user: record.user,
                        },
                        input_rx,
                        || {
                            let _ = started.send(());
                        },
                        |chunk| {
                            let _ = output.blocking_send(chunk);
                        },
                    )?)
                })();
                drop(output);
                tracing::debug!(channel = ?id, succeeded = value.is_ok(), "SSH guest command finished");
                let _ = finished.send(value);
            });
        if spawned.is_err() {
            if let Some(reply) = reply {
                reply
                    .reject(russh::ChannelOpenFailure::ResourceShortage)
                    .await;
            } else {
                let _ = writer.exit_status(255).await;
                let _ = writer.close().await;
            }
            return;
        }
        let control_task = AbortOnDrop(tokio::spawn(async move {
            // Controls may arrive immediately after exec; don't race the guest
            // registration. This wait never blocks the SSH connection handler.
            if ready.await.is_err() {
                return;
            }
            while let Some(action) = requests.recv().await {
                let machine = control_machine.clone();
                let id = control_id.clone();
                let count = ActiveThread::new(active.clone());
                let result = tokio::task::spawn_blocking(move || {
                    let _count = count;
                    let manager = AgentManager::for_vm(&machine)?;
                    let mut client = AgentClient::connect(manager.vsock_socket())?;
                    let _deadline = client.set_extended_read_timeout(Duration::from_secs(3))?;
                    client.interactive_control(Request { id, action })
                })
                .await;
                // Signal and window-change requests have no SSH reply. A late
                // control can legitimately race process exit; preserve output.
                if !matches!(result, Ok(Ok(()))) {
                    tracing::debug!("SSH guest control raced completion or failed");
                }
            }
        }));
        let input_task = AbortOnDrop(tokio::spawn(async move {
            while let Some(data) = receiver.recv().await {
                let size = data.as_ref().map_or(0, Vec::len);
                let event = match data {
                    Some(bytes) => InteractiveInput::Stdin(bytes),
                    None => InteractiveInput::Eof,
                };
                if input.send(event).await.is_err() {
                    break;
                }
                queued.fetch_sub(size, Ordering::SeqCst);
                if size > 0 && handle.consume_window(id, size as u32).await.is_err() {
                    break;
                }
                // Keep the sender alive after EOF: only channel close cancels
                // the guest, and it must still be able to produce output.
            }
        }));
        let output_writer = writer.clone();
        let output_accepted = accepted.clone();
        let mut output_task = AbortOnDrop(tokio::spawn(async move {
            if let Some(reply) = reply {
                let result =
                    super::forward::output(output_rx, output_writer, reply, output_accepted).await;
                tracing::debug!(succeeded = result.is_ok(), "SSH TCP relay finished");
                return;
            }
            while let Some(chunk) = output_rx.recv().await {
                let sent = match chunk {
                    InteractiveOutput::Stdout(data) => output_writer.data_bytes(data).await,
                    InteractiveOutput::Stderr(data) => {
                        output_writer.extended_data_bytes(1, data).await
                    }
                };
                if sent.is_err() {
                    break;
                }
            }
        }));
        let mut done = done;
        let mut input_task = Some(input_task);
        let result = tokio::select! {
            result = &mut done => {
                // Drain all buffered output before reporting normal completion.
                let _ = (&mut output_task.0).await;
                result
            }
            _ = &mut output_task.0 => {
                // A failed destination or blocked startup deadline must cancel
                // the guest even while DNS, stdin or its output is still blocked.
                drop(input_task.take());
                done.await
            }
        };
        drop(output_task);
        drop(input_task);
        drop(control_task);
        let code = match result {
            Ok(Ok(code)) => u32::try_from(code).unwrap_or(255),
            _ => 255,
        };
        if !forwarding {
            let _ = writer.exit_status(code).await;
            let _ = writer.eof().await;
        }
        if !forwarding || accepted.load(Ordering::SeqCst) {
            let _ = writer.close().await;
        }
    });
    (task, controls)
}
