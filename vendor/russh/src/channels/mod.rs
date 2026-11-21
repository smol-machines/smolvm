use std::sync::Arc;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{Mutex, Notify};

use crate::{ChannelId, ChannelOpenFailure, Error, Pty, Sig};

pub mod io;

mod channel_ref;
pub use channel_ref::ChannelRef;

mod channel_stream;
pub use channel_stream::ChannelStream;

#[derive(Debug)]
#[non_exhaustive]
/// Possible messages that [Channel::wait] can receive.
pub enum ChannelMsg {
    Open {
        id: ChannelId,
        max_packet_size: u32,
        window_size: u32,
    },
    Data {
        data: Bytes,
    },
    ExtendedData {
        data: Bytes,
        ext: u32,
    },
    Eof,
    Close,
    /// (client only)
    RequestPty {
        want_reply: bool,
        term: String,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        terminal_modes: Vec<(Pty, u32)>,
    },
    /// (client only)
    RequestShell {
        want_reply: bool,
    },
    /// (client only)
    Exec {
        want_reply: bool,
        command: Vec<u8>,
    },
    /// (client only)
    Signal {
        signal: Sig,
    },
    /// (client only)
    RequestSubsystem {
        want_reply: bool,
        name: String,
    },
    /// (client only)
    RequestX11 {
        want_reply: bool,
        single_connection: bool,
        x11_authentication_protocol: String,
        x11_authentication_cookie: String,
        x11_screen_number: u32,
    },
    /// (client only)
    SetEnv {
        want_reply: bool,
        variable_name: String,
        variable_value: String,
    },
    /// (client only)
    WindowChange {
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
    },
    /// (client only)
    AgentForward {
        want_reply: bool,
    },

    /// (server only)
    XonXoff {
        client_can_do: bool,
    },
    /// (server only)
    ExitStatus {
        exit_status: u32,
    },
    /// (server only)
    ExitSignal {
        signal_name: Sig,
        core_dumped: bool,
        error_message: String,
        lang_tag: String,
    },
    /// (server only)
    WindowAdjusted {
        new_size: u32,
    },
    /// (server only)
    Success,
    /// (server only)
    Failure,
    OpenFailure(ChannelOpenFailure),
}

#[derive(Clone, Debug)]
pub(crate) struct WindowSizeRef {
    value: Arc<Mutex<u32>>,
    notifier: Arc<Notify>,
}

impl WindowSizeRef {
    pub(crate) fn new(initial: u32) -> Self {
        let notifier = Arc::new(Notify::new());
        Self {
            value: Arc::new(Mutex::new(initial)),
            notifier,
        }
    }

    pub(crate) async fn grow(&self, amount: u32) {
        let mut value = self.value.lock().await;
        *value = value.saturating_add(amount);
        drop(value);
        self.notifier.notify_one();
    }

    pub(crate) fn subscribe(&self) -> Arc<Notify> {
        Arc::clone(&self.notifier)
    }
}

/// A handle to the reading part of a session channel.
///
/// Allows you to read from a channel without borrowing the session
pub struct ChannelReadHalf {
    pub(crate) receiver: Receiver<ChannelMsg>,
}

impl std::fmt::Debug for ChannelReadHalf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChannelReadHalf").finish()
    }
}

impl ChannelReadHalf {
    /// Awaits an incoming [`ChannelMsg`], this method returns [`None`] if the channel has been closed.
    pub async fn wait(&mut self) -> Option<ChannelMsg> {
        self.receiver.recv().await
    }

    /// Make a reader for the [`Channel`] to receive [`ChannelMsg::Data`]
    /// through the `AsyncRead` trait.
    pub fn make_reader(&mut self) -> impl AsyncRead + '_ {
        self.make_reader_ext(None)
    }

    /// Make a reader for the [`Channel`] to receive [`ChannelMsg::Data`] or [`ChannelMsg::ExtendedData`]
    /// depending on the `ext` parameter, through the `AsyncRead` trait.
    pub fn make_reader_ext(&mut self, ext: Option<u32>) -> impl AsyncRead + '_ {
        io::ChannelRx::new(self, ext)
    }
}

/// A handle to the writing part of a session channel.
///
/// Allows you to write to a channel without borrowing the session
pub struct ChannelWriteHalf<Send: From<(ChannelId, ChannelMsg)>> {
    pub(crate) id: ChannelId,
    pub(crate) sender: Sender<Send>,
    pub(crate) max_packet_size: u32,
    pub(crate) window_size: WindowSizeRef,
}

impl<S: From<(ChannelId, ChannelMsg)>> std::fmt::Debug for ChannelWriteHalf<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChannelWriteHalf")
            .field("id", &self.id)
            .finish()
    }
}

impl<S: From<(ChannelId, ChannelMsg)> + Send + Sync + 'static> ChannelWriteHalf<S> {
    /// Returns the min between the maximum packet size and the
    /// remaining window size in the channel.
    pub async fn writable_packet_size(&self) -> usize {
        self.max_packet_size
            .min(*self.window_size.value.lock().await) as usize
    }

    pub fn id(&self) -> ChannelId {
        self.id
    }

    /// Request a pseudo-terminal with the given characteristics.
    #[allow(clippy::too_many_arguments)] // length checked
    pub async fn request_pty(
        &self,
        want_reply: bool,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        terminal_modes: &[(Pty, u32)],
    ) -> Result<(), Error> {
        self.send_msg(ChannelMsg::RequestPty {
            want_reply,
            term: term.to_string(),
            col_width,
            row_height,
            pix_width,
            pix_height,
            terminal_modes: terminal_modes.to_vec(),
        })
        .await
    }

    /// Request a remote shell.
    pub async fn request_shell(&self, want_reply: bool) -> Result<(), Error> {
        self.send_msg(ChannelMsg::RequestShell { want_reply }).await
    }

    /// Execute a remote program (will be passed to a shell). This can
    /// be used to implement scp (by calling a remote scp and
    /// tunneling to its standard input).
    pub async fn exec<A: Into<Vec<u8>>>(&self, want_reply: bool, command: A) -> Result<(), Error> {
        self.send_msg(ChannelMsg::Exec {
            want_reply,
            command: command.into(),
        })
        .await
    }

    /// Signal a remote process.
    pub async fn signal(&self, signal: Sig) -> Result<(), Error> {
        self.send_msg(ChannelMsg::Signal { signal }).await
    }

    /// Request the start of a subsystem with the given name.
    pub async fn request_subsystem<A: Into<String>>(
        &self,
        want_reply: bool,
        name: A,
    ) -> Result<(), Error> {
        self.send_msg(ChannelMsg::RequestSubsystem {
            want_reply,
            name: name.into(),
        })
        .await
    }

    /// Request X11 forwarding through an already opened X11
    /// channel. See
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-6.3.1)
    /// for security issues related to cookies.
    pub async fn request_x11<A: Into<String>, B: Into<String>>(
        &self,
        want_reply: bool,
        single_connection: bool,
        x11_authentication_protocol: A,
        x11_authentication_cookie: B,
        x11_screen_number: u32,
    ) -> Result<(), Error> {
        self.send_msg(ChannelMsg::RequestX11 {
            want_reply,
            single_connection,
            x11_authentication_protocol: x11_authentication_protocol.into(),
            x11_authentication_cookie: x11_authentication_cookie.into(),
            x11_screen_number,
        })
        .await
    }

    /// Set a remote environment variable.
    pub async fn set_env<A: Into<String>, B: Into<String>>(
        &self,
        want_reply: bool,
        variable_name: A,
        variable_value: B,
    ) -> Result<(), Error> {
        self.send_msg(ChannelMsg::SetEnv {
            want_reply,
            variable_name: variable_name.into(),
            variable_value: variable_value.into(),
        })
        .await
    }

    /// Inform the server that our window size has changed.
    pub async fn window_change(
        &self,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
    ) -> Result<(), Error> {
        self.send_msg(ChannelMsg::WindowChange {
            col_width,
            row_height,
            pix_width,
            pix_height,
        })
        .await
    }

    /// Inform the server that we will accept agent forwarding channels
    pub async fn agent_forward(&self, want_reply: bool) -> Result<(), Error> {
        self.send_msg(ChannelMsg::AgentForward { want_reply }).await
    }

    /// Send data to a channel.
    pub async fn data<R: tokio::io::AsyncRead + Unpin>(&self, data: R) -> Result<(), Error> {
        self.send_data(None, data).await
    }

    /// Send owned bytes to a channel without copying them into the `AsyncWrite` path.
    pub async fn data_bytes(&self, data: impl Into<Bytes>) -> Result<(), Error> {
        self.send_bytes(None, data.into()).await
    }

    /// Send data to a channel. The number of bytes added to the
    /// "sending pipeline" (to be processed by the event loop) is
    /// returned.
    pub async fn extended_data<R: tokio::io::AsyncRead + Unpin>(
        &self,
        ext: u32,
        data: R,
    ) -> Result<(), Error> {
        self.send_data(Some(ext), data).await
    }

    /// Send owned extended data to a channel without copying it into the `AsyncWrite` path.
    pub async fn extended_data_bytes(
        &self,
        ext: u32,
        data: impl Into<Bytes>,
    ) -> Result<(), Error> {
        self.send_bytes(Some(ext), data.into()).await
    }

    async fn send_data<R: tokio::io::AsyncRead + Unpin>(
        &self,
        ext: Option<u32>,
        mut data: R,
    ) -> Result<(), Error> {
        let mut tx = self.make_writer_ext(ext);

        tokio::io::copy(&mut data, &mut tx).await?;

        Ok(())
    }

    async fn reserve_writable_chunk(&self, remaining: usize) -> Result<usize, Error> {
        if self.max_packet_size == 0 {
            return Err(Error::Inconsistent);
        }
        loop {
            let mut window_size = self.window_size.value.lock().await;
            let writable = (self.max_packet_size as usize)
                .min(*window_size as usize)
                .min(remaining);
            if writable > 0 {
                *window_size -= writable as u32;
                if *window_size > 0 {
                    self.window_size.notifier.notify_one();
                }
                return Ok(writable);
            }
            let notified = self.window_size.notifier.notified();
            drop(window_size);
            notified.await;
        }
    }

    async fn send_bytes(&self, ext: Option<u32>, data: Bytes) -> Result<(), Error> {
        if data.is_empty() {
            return Ok(());
        }

        let mut offset = 0;
        while offset < data.len() {
            let writable = self.reserve_writable_chunk(data.len() - offset).await?;
            let end = offset + writable;
            let chunk = data.slice(offset..end);
            let msg = match ext {
                None => ChannelMsg::Data { data: chunk },
                Some(ext) => ChannelMsg::ExtendedData { data: chunk, ext },
            };
            self.send_msg(msg).await?;
            offset = end;
        }

        Ok(())
    }

    pub async fn eof(&self) -> Result<(), Error> {
        self.send_msg(ChannelMsg::Eof).await
    }

    pub async fn exit_status(&self, exit_status: u32) -> Result<(), Error> {
        self.send_msg(ChannelMsg::ExitStatus { exit_status }).await
    }

    /// Request that the channel be closed.
    pub async fn close(&self) -> Result<(), Error> {
        self.send_msg(ChannelMsg::Close).await
    }

    async fn send_msg(&self, msg: ChannelMsg) -> Result<(), Error> {
        self.sender
            .send((self.id, msg).into())
            .await
            .map_err(|_| Error::SendError)
    }

    /// Make a writer for the [`Channel`] to send [`ChannelMsg::Data`]
    /// through the `AsyncWrite` trait.
    pub fn make_writer(&self) -> impl AsyncWrite + 'static {
        self.make_writer_ext(None)
    }

    /// Make a writer for the [`Channel`] to send [`ChannelMsg::Data`] or [`ChannelMsg::ExtendedData`]
    /// depending on the `ext` parameter, through the `AsyncWrite` trait.
    pub fn make_writer_ext(&self, ext: Option<u32>) -> impl AsyncWrite + 'static {
        io::ChannelTx::new(
            self.sender.clone(),
            self.id,
            self.window_size.value.clone(),
            self.window_size.subscribe(),
            self.max_packet_size,
            ext,
        )
    }
}

/// A handle to a session channel.
///
/// Allows you to read and write from a channel without borrowing the session
pub struct Channel<Send: From<(ChannelId, ChannelMsg)>> {
    pub(crate) read_half: ChannelReadHalf,
    pub(crate) write_half: ChannelWriteHalf<Send>,
}

impl<T: From<(ChannelId, ChannelMsg)>> std::fmt::Debug for Channel<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Channel")
            .field("id", &self.write_half.id)
            .finish()
    }
}

impl<S: From<(ChannelId, ChannelMsg)> + Send + Sync + 'static> Channel<S> {
    pub(crate) fn new(
        id: ChannelId,
        sender: Sender<S>,
        max_packet_size: u32,
        window_size: u32,
        channel_buffer_size: usize,
    ) -> (Self, ChannelRef) {
        let (tx, rx) = tokio::sync::mpsc::channel(channel_buffer_size);
        let window_size = WindowSizeRef::new(window_size);
        let read_half = ChannelReadHalf { receiver: rx };
        let write_half = ChannelWriteHalf {
            id,
            sender,
            max_packet_size,
            window_size: window_size.clone(),
        };

        (
            Self {
                write_half,
                read_half,
            },
            ChannelRef {
                sender: tx,
                window_size,
            },
        )
    }

    /// Returns the min between the maximum packet size and the
    /// remaining window size in the channel.
    pub async fn writable_packet_size(&self) -> usize {
        self.write_half.writable_packet_size().await
    }

    pub fn id(&self) -> ChannelId {
        self.write_half.id()
    }

    /// Split this [`Channel`] into a [`ChannelReadHalf`] and a [`ChannelWriteHalf`], which can be
    /// used to read and write concurrently.
    pub fn split(self) -> (ChannelReadHalf, ChannelWriteHalf<S>) {
        (self.read_half, self.write_half)
    }

    /// Request a pseudo-terminal with the given characteristics.
    #[allow(clippy::too_many_arguments)] // length checked
    pub async fn request_pty(
        &self,
        want_reply: bool,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        terminal_modes: &[(Pty, u32)],
    ) -> Result<(), Error> {
        self.write_half
            .request_pty(
                want_reply,
                term,
                col_width,
                row_height,
                pix_width,
                pix_height,
                terminal_modes,
            )
            .await
    }

    /// Request a remote shell.
    pub async fn request_shell(&self, want_reply: bool) -> Result<(), Error> {
        self.write_half.request_shell(want_reply).await
    }

    /// Execute a remote program (will be passed to a shell). This can
    /// be used to implement scp (by calling a remote scp and
    /// tunneling to its standard input).
    pub async fn exec<A: Into<Vec<u8>>>(&self, want_reply: bool, command: A) -> Result<(), Error> {
        self.write_half.exec(want_reply, command).await
    }

    /// Signal a remote process.
    pub async fn signal(&self, signal: Sig) -> Result<(), Error> {
        self.write_half.signal(signal).await
    }

    /// Request the start of a subsystem with the given name.
    pub async fn request_subsystem<A: Into<String>>(
        &self,
        want_reply: bool,
        name: A,
    ) -> Result<(), Error> {
        self.write_half.request_subsystem(want_reply, name).await
    }

    /// Request X11 forwarding through an already opened X11
    /// channel. See
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-6.3.1)
    /// for security issues related to cookies.
    pub async fn request_x11<A: Into<String>, B: Into<String>>(
        &self,
        want_reply: bool,
        single_connection: bool,
        x11_authentication_protocol: A,
        x11_authentication_cookie: B,
        x11_screen_number: u32,
    ) -> Result<(), Error> {
        self.write_half
            .request_x11(
                want_reply,
                single_connection,
                x11_authentication_protocol,
                x11_authentication_cookie,
                x11_screen_number,
            )
            .await
    }

    /// Set a remote environment variable.
    pub async fn set_env<A: Into<String>, B: Into<String>>(
        &self,
        want_reply: bool,
        variable_name: A,
        variable_value: B,
    ) -> Result<(), Error> {
        self.write_half
            .set_env(want_reply, variable_name, variable_value)
            .await
    }

    /// Inform the server that our window size has changed.
    pub async fn window_change(
        &self,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
    ) -> Result<(), Error> {
        self.write_half
            .window_change(col_width, row_height, pix_width, pix_height)
            .await
    }

    /// Inform the server that we will accept agent forwarding channels
    pub async fn agent_forward(&self, want_reply: bool) -> Result<(), Error> {
        self.write_half.agent_forward(want_reply).await
    }

    /// Send data to a channel.
    pub async fn data<R: tokio::io::AsyncRead + Unpin>(&self, data: R) -> Result<(), Error> {
        self.write_half.data(data).await
    }

    /// Send owned bytes to a channel without copying them into the `AsyncWrite` path.
    pub async fn data_bytes(&self, data: impl Into<Bytes>) -> Result<(), Error> {
        self.write_half.data_bytes(data).await
    }

    /// Send data to a channel. The number of bytes added to the
    /// "sending pipeline" (to be processed by the event loop) is
    /// returned.
    pub async fn extended_data<R: tokio::io::AsyncRead + Unpin>(
        &self,
        ext: u32,
        data: R,
    ) -> Result<(), Error> {
        self.write_half.extended_data(ext, data).await
    }

    /// Send owned extended data to a channel without copying it into the `AsyncWrite` path.
    pub async fn extended_data_bytes(
        &self,
        ext: u32,
        data: impl Into<Bytes>,
    ) -> Result<(), Error> {
        self.write_half.extended_data_bytes(ext, data).await
    }

    pub async fn eof(&self) -> Result<(), Error> {
        self.write_half.eof().await
    }

    pub async fn exit_status(&self, exit_status: u32) -> Result<(), Error> {
        self.write_half.exit_status(exit_status).await
    }

    /// Request that the channel be closed.
    pub async fn close(&self) -> Result<(), Error> {
        self.write_half.close().await
    }

    /// Awaits an incoming [`ChannelMsg`], this method returns [`None`] if the channel has been closed.
    pub async fn wait(&mut self) -> Option<ChannelMsg> {
        self.read_half.wait().await
    }

    /// Consume the [`Channel`] to produce a bidirectionnal stream,
    /// sending and receiving [`ChannelMsg::Data`] as `AsyncRead` + `AsyncWrite`.
    pub fn into_stream(self) -> ChannelStream<S> {
        ChannelStream::new(
            io::ChannelTx::new(
                self.write_half.sender.clone(),
                self.write_half.id,
                self.write_half.window_size.value.clone(),
                self.write_half.window_size.subscribe(),
                self.write_half.max_packet_size,
                None,
            ),
            io::ChannelRx::new(io::ChannelCloseOnDrop(self), None),
        )
    }

    /// Make a reader for the [`Channel`] to receive [`ChannelMsg::Data`]
    /// through the `AsyncRead` trait.
    pub fn make_reader(&mut self) -> impl AsyncRead + '_ {
        self.read_half.make_reader()
    }

    /// Make a reader for the [`Channel`] to receive [`ChannelMsg::Data`] or [`ChannelMsg::ExtendedData`]
    /// depending on the `ext` parameter, through the `AsyncRead` trait.
    pub fn make_reader_ext(&mut self, ext: Option<u32>) -> impl AsyncRead + '_ {
        self.read_half.make_reader_ext(ext)
    }

    /// Make a writer for the [`Channel`] to send [`ChannelMsg::Data`]
    /// through the `AsyncWrite` trait.
    pub fn make_writer(&self) -> impl AsyncWrite + 'static {
        self.write_half.make_writer()
    }

    /// Make a writer for the [`Channel`] to send [`ChannelMsg::Data`] or [`ChannelMsg::ExtendedData`]
    /// depending on the `ext` parameter, through the `AsyncWrite` trait.
    pub fn make_writer_ext(&self, ext: Option<u32>) -> impl AsyncWrite + 'static {
        self.write_half.make_writer_ext(ext)
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::mpsc;

    use super::*;

    fn test_write_half(
        window_size: WindowSizeRef,
        max_packet_size: u32,
    ) -> (
        ChannelWriteHalf<(ChannelId, ChannelMsg)>,
        mpsc::Receiver<(ChannelId, ChannelMsg)>,
    ) {
        let (sender, receiver) = mpsc::channel(8);
        (
            ChannelWriteHalf {
                id: ChannelId(7),
                sender,
                max_packet_size,
                window_size,
            },
            receiver,
        )
    }

    #[tokio::test]
    async fn data_bytes_sends_one_owned_message_when_window_permits() {
        let payload = Bytes::from_static(b"owned data");
        let (write_half, mut receiver) = test_write_half(WindowSizeRef::new(1024), 1024);

        write_half.data_bytes(payload.clone()).await.unwrap();

        match receiver.recv().await.unwrap() {
            (ChannelId(7), ChannelMsg::Data { data }) => {
                assert_eq!(data, payload);
                assert_eq!(data.as_ptr(), payload.as_ptr());
            }
            msg => panic!("unexpected message: {msg:?}"),
        }
    }

    #[tokio::test]
    async fn data_bytes_splits_by_max_packet_size_without_copying() {
        let payload = Bytes::from_static(b"abcdefghij");
        let (write_half, mut receiver) = test_write_half(WindowSizeRef::new(1024), 4);

        write_half.data_bytes(payload.clone()).await.unwrap();

        for (range, expected) in [
            (0..4, &b"abcd"[..]),
            (4..8, &b"efgh"[..]),
            (8..10, &b"ij"[..]),
        ] {
            match receiver.recv().await.unwrap() {
                (ChannelId(7), ChannelMsg::Data { data }) => {
                    assert_eq!(data.as_ref(), expected);
                    assert_eq!(data.as_ptr(), payload.slice(range).as_ptr());
                }
                msg => panic!("unexpected message: {msg:?}"),
            }
        }
        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn extended_data_bytes_preserves_extension_code() {
        let payload = Bytes::from_static(b"stderr");
        let (write_half, mut receiver) = test_write_half(WindowSizeRef::new(1024), 1024);

        write_half
            .extended_data_bytes(1, payload.clone())
            .await
            .unwrap();

        match receiver.recv().await.unwrap() {
            (ChannelId(7), ChannelMsg::ExtendedData { data, ext }) => {
                assert_eq!(ext, 1);
                assert_eq!(data, payload);
                assert_eq!(data.as_ptr(), payload.as_ptr());
            }
            msg => panic!("unexpected message: {msg:?}"),
        }
    }

    #[tokio::test]
    async fn data_bytes_empty_payload_sends_nothing() {
        let (write_half, mut receiver) = test_write_half(WindowSizeRef::new(1024), 1024);

        write_half.data_bytes(Bytes::new()).await.unwrap();

        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn data_bytes_waits_for_window_update() {
        let window_size = WindowSizeRef::new(0);
        let (write_half, mut receiver) = test_write_half(window_size.clone(), 1024);
        let send = tokio::spawn(async move {
            write_half
                .data_bytes(Bytes::from_static(b"after-window"))
                .await
                .unwrap();
        });

        tokio::task::yield_now().await;
        assert!(!send.is_finished());

        window_size.grow(1024).await;
        send.await.unwrap();

        match receiver.recv().await.unwrap() {
            (ChannelId(7), ChannelMsg::Data { data }) => {
                assert_eq!(data.as_ref(), b"after-window");
            }
            msg => panic!("unexpected message: {msg:?}"),
        }
    }

    #[tokio::test]
    async fn data_bytes_rejects_zero_max_packet_size() {
        let (write_half, mut receiver) = test_write_half(WindowSizeRef::new(1024), 0);

        let result = write_half.data_bytes(Bytes::from_static(b"owned")).await;

        assert!(matches!(result, Err(Error::Inconsistent)));
        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn channel_data_bytes_forwards_to_write_half() {
        let (sender, mut receiver) = mpsc::channel(8);
        let (channel, _reference) =
            Channel::<(ChannelId, ChannelMsg)>::new(ChannelId(9), sender, 1024, 1024, 8);

        channel.data_bytes(Bytes::from_static(b"channel")).await.unwrap();

        match receiver.recv().await.unwrap() {
            (ChannelId(9), ChannelMsg::Data { data }) => {
                assert_eq!(data.as_ref(), b"channel");
            }
            msg => panic!("unexpected message: {msg:?}"),
        }
    }
}
