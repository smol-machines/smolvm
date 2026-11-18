//! Bounded SSH channel handling for a single on-demand client connection.
use anyhow::Result;
use russh::{server, Channel, ChannelId, ChannelWriteHalf};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
use tokio::sync::{mpsc, oneshot};

use super::guest;

pub(super) const WINDOW: usize = 65536;
const CHANNELS: usize = 32;
#[derive(Default)]
pub(super) struct Metrics {
    pub(super) authenticated: AtomicUsize,
    pub(super) denied: AtomicUsize,
    pub(super) channels: AtomicUsize,
    pub(super) max_queued: AtomicUsize,
    pub(super) guest_threads: Arc<AtomicUsize>,
}
pub(super) struct Input {
    sender: mpsc::UnboundedSender<Option<Vec<u8>>>,
    receiver: Option<mpsc::UnboundedReceiver<Option<Vec<u8>>>>,
    writer: Option<ChannelWriteHalf<server::Msg>>,
    task: Option<tokio::task::JoinHandle<()>>,
    queued: Arc<AtomicUsize>,
    eof: bool,
    metrics: Arc<Metrics>,
    terminal: Option<crate::agent::interactive_control::Terminal>,
    term: Option<String>,
    controls: Option<mpsc::Sender<crate::agent::interactive_control::Action>>,
}
impl Drop for Input {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
        self.metrics.channels.fetch_sub(1, Ordering::SeqCst);
    }
}
pub(super) struct Handler {
    pub(super) machine: String,
    pub(super) expected_host: Arc<russh::keys::PublicKey>,
    pub(super) allowed: Arc<russh::keys::PublicKey>,
    pub(super) authenticated: Option<oneshot::Sender<()>>,
    pub(super) inputs: HashMap<ChannelId, Input>,
    pub(super) metrics: Arc<Metrics>,
}
impl Handler {
    fn queue_control(
        &mut self,
        id: ChannelId,
        action: crate::agent::interactive_control::Action,
        session: &mut server::Session,
    ) -> Result<(), russh::Error> {
        let Some(sender) = self
            .inputs
            .get(&id)
            .and_then(|input| input.controls.as_ref())
        else {
            return Ok(());
        };
        if sender.try_send(action).is_err() {
            // Bound hostile control floods without stalling unrelated channels.
            self.inputs.remove(&id);
            session.close(id)?;
        }
        Ok(())
    }
    fn admit(&mut self, channel: Channel<server::Msg>) -> Option<ChannelId> {
        // A locally closed channel can be removed by russh before its peer
        // close reaches the callback. Reap completed workers before admission.
        self.inputs
            .retain(|_, input| !input.task.as_ref().is_some_and(|task| task.is_finished()));
        if self.inputs.len() >= CHANNELS {
            return None;
        }
        let id = channel.id();
        let (read, write) = channel.split();
        // Deliver inbound bytes through the handler only; retain the bounded
        // remote-window-aware writer, not the library's duplicate read queue.
        drop(read);
        let (sender, receiver) = mpsc::unbounded_channel();
        self.metrics.channels.fetch_add(1, Ordering::SeqCst);
        self.inputs.insert(
            id,
            Input {
                sender,
                receiver: Some(receiver),
                writer: Some(write),
                task: None,
                queued: Arc::default(),
                eof: false,
                metrics: self.metrics.clone(),
                terminal: None,
                term: None,
                controls: None,
            },
        );
        Some(id)
    }
    fn authorize(&self, user: &str, key: &russh::keys::PublicKey) -> server::Auth {
        if user == "smol" && key.key_data() == self.allowed.key_data() {
            server::Auth::Accept
        } else {
            self.metrics.denied.fetch_add(1, Ordering::SeqCst);
            server::Auth::reject()
        }
    }
}
impl server::Handler for Handler {
    type Error = russh::Error;
    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        key: server::PublicKeyOffer<'_>,
    ) -> Result<server::Auth, Self::Error> {
        Ok(self.authorize(user, key.public_key))
    }
    async fn auth_publickey(
        &mut self,
        user: &str,
        key: server::VerifiedPublicKey<'_>,
    ) -> Result<server::Auth, Self::Error> {
        Ok(self.authorize(user, key.public_key))
    }
    async fn auth_succeeded(&mut self, _: &mut server::Session) -> Result<(), Self::Error> {
        self.metrics.authenticated.fetch_add(1, Ordering::SeqCst);
        if let Some(ready) = self.authenticated.take() {
            let _ = ready.send(());
        }
        Ok(())
    }
    async fn channel_open_session(
        &mut self,
        channel: Channel<server::Msg>,
        reply: server::ChannelOpenHandle,
        _: &mut server::Session,
    ) -> Result<(), Self::Error> {
        if self.admit(channel).is_none() {
            reply
                .reject(russh::ChannelOpenFailure::ResourceShortage)
                .await;
            return Ok(());
        }
        reply.accept().await;
        Ok(())
    }
    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<server::Msg>,
        host: &str,
        port: u32,
        _: &str,
        _: u32,
        reply: server::ChannelOpenHandle,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        let Ok(port) = u16::try_from(port) else {
            return Ok(());
        };
        if (crate::agent::interactive_control::Builtin::TcpConnect {
            host: host.into(),
            port,
        })
        .validate()
        .is_err()
        {
            return Ok(());
        }
        let Some(id) = self.admit(channel) else {
            reply
                .reject(russh::ChannelOpenFailure::ResourceShortage)
                .await;
            return Ok(());
        };
        let input = self.inputs.get_mut(&id).unwrap();
        let (task, _) = guest::start(
            id,
            input.receiver.take().unwrap(),
            input.writer.take().unwrap(),
            input.queued.clone(),
            session.handle(),
            self.machine.clone(),
            self.expected_host.clone(),
            guest::Operation::Tcp {
                host: host.into(),
                port,
                reply,
            },
            self.metrics.guest_threads.clone(),
        );
        input.task = Some(task);
        Ok(())
    }
    async fn exec_request(
        &mut self,
        id: ChannelId,
        command: &[u8],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        let Some(input) = self.inputs.get_mut(&id) else {
            return Err(russh::Error::Inconsistent);
        };
        let supported = command.len() <= 64 * 1024
            && std::str::from_utf8(command).is_ok()
            && !command.contains(&0);
        if input.task.is_some() || !supported {
            session.channel_failure(id)?;
            return Ok(());
        }
        session.channel_success(id)?;
        {
            let (task, controls) = guest::start(
                id,
                input.receiver.take().unwrap(),
                input.writer.take().unwrap(),
                input.queued.clone(),
                session.handle(),
                self.machine.clone(),
                self.expected_host.clone(),
                guest::Operation::Execute {
                    command: String::from_utf8(command.to_vec()).unwrap(),
                    terminal: input.terminal.clone(),
                    env: input
                        .term
                        .clone()
                        .map(|term| ("TERM".into(), term))
                        .into_iter()
                        .collect(),
                },
                self.metrics.guest_threads.clone(),
            );
            input.task = Some(task);
            input.controls = Some(controls);
            Ok(())
        }
    }
    async fn data(
        &mut self,
        id: ChannelId,
        data: &[u8],
        _: &mut server::Session,
    ) -> Result<(), Self::Error> {
        let input = self.inputs.get(&id).ok_or(russh::Error::Inconsistent)?;
        // Empty packets consume no SSH credit and must not allocate queue entries.
        if data.is_empty() {
            return Ok(());
        }
        if input.eof {
            return Err(russh::Error::Inconsistent);
        }
        let size = input.queued.fetch_add(data.len(), Ordering::SeqCst) + data.len();
        if size > WINDOW {
            return Err(russh::Error::Inconsistent);
        }
        self.metrics.max_queued.fetch_max(size, Ordering::SeqCst);
        input
            .sender
            .send(Some(data.to_vec()))
            .map_err(|_| russh::Error::Inconsistent)
    }
    async fn shell_request(
        &mut self,
        id: ChannelId,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        {
            self.exec_request(id, b"exec /bin/sh -l", session).await
        }
    }
    async fn subsystem_request(
        &mut self,
        id: ChannelId,
        name: &str,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        let Some(input) = self.inputs.get_mut(&id) else {
            return Ok(());
        };
        if name != "sftp" || input.task.is_some() || input.terminal.is_some() {
            session.channel_failure(id)?;
            return Ok(());
        }
        session.channel_success(id)?;
        let (task, _) = guest::start(
            id,
            input.receiver.take().unwrap(),
            input.writer.take().unwrap(),
            input.queued.clone(),
            session.handle(),
            self.machine.clone(),
            self.expected_host.clone(),
            guest::Operation::Sftp,
            self.metrics.guest_threads.clone(),
        );
        input.task = Some(task);
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    async fn pty_request(
        &mut self,
        id: ChannelId,
        term: &str,
        cols: u32,
        rows: u32,
        _: u32,
        _: u32,
        modes: &[(russh::Pty, u32)],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        {
            let Some(input) = self.inputs.get_mut(&id) else {
                return Ok(());
            };
            if input.task.is_some()
                || input.terminal.is_some()
                || modes.len() > 128
                || term.len() > 128
                || term.contains('\0')
            {
                return session.channel_failure(id);
            }
            let (Ok(cols), Ok(rows)) = (u16::try_from(cols), u16::try_from(rows)) else {
                return session.channel_failure(id);
            };
            input.terminal = Some(crate::agent::interactive_control::Terminal {
                cols: if cols == 0 { 80 } else { cols },
                rows: if rows == 0 { 24 } else { rows },
                modes: modes
                    .iter()
                    .map(|&(mode, value)| (mode as u8, value))
                    .collect(),
            });
            input.term = Some(term.into());
            session.channel_success(id)
        }
    }
    async fn window_change_request(
        &mut self,
        id: ChannelId,
        cols: u32,
        rows: u32,
        _: u32,
        _: u32,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        {
            let (Ok(cols), Ok(rows)) = (u16::try_from(cols), u16::try_from(rows)) else {
                return Ok(());
            };
            if cols == 0 && rows == 0 {
                return Ok(());
            }
            let Some(input) = self.inputs.get_mut(&id) else {
                return Ok(());
            };
            let Some(terminal) = input.terminal.as_mut() else {
                return Ok(());
            };
            // SSH zero dimensions leave that axis unchanged.
            let cols = if cols == 0 { terminal.cols } else { cols };
            let rows = if rows == 0 { terminal.rows } else { rows };
            terminal.cols = cols;
            terminal.rows = rows;
            if input.task.is_some() {
                self.queue_control(
                    id,
                    crate::agent::interactive_control::Action::Resize { cols, rows },
                    session,
                )?;
            }
        }
        Ok(())
    }
    async fn signal(
        &mut self,
        id: ChannelId,
        signal: russh::Sig,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        {
            let signal = match signal {
                russh::Sig::HUP => 1,
                russh::Sig::INT => 2,
                russh::Sig::QUIT => 3,
                russh::Sig::ILL => 4,
                russh::Sig::ABRT => 6,
                russh::Sig::FPE => 8,
                russh::Sig::KILL => 9,
                russh::Sig::SEGV => 11,
                russh::Sig::PIPE => 13,
                russh::Sig::ALRM => 14,
                russh::Sig::TERM => 15,
                russh::Sig::USR1 => 10,
                russh::Sig::Custom(name) if name == "USR2" => 12,
                _ => return Ok(()),
            };
            self.queue_control(
                id,
                crate::agent::interactive_control::Action::Signal { signal },
                session,
            )?;
        }
        Ok(())
    }
    async fn channel_eof(
        &mut self,
        id: ChannelId,
        _: &mut server::Session,
    ) -> Result<(), Self::Error> {
        if let Some(input) = self.inputs.get_mut(&id) {
            if !input.eof {
                input.eof = true;
                let _ = input.sender.send(None);
            }
        }
        Ok(())
    }
    async fn channel_close(
        &mut self,
        id: ChannelId,
        _: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.inputs.remove(&id);
        Ok(())
    }
}
