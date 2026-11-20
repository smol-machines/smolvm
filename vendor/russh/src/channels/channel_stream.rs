use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite};

use super::io::{ChannelCloseOnDrop, ChannelRx, ChannelTx};
use super::{ChannelId, ChannelMsg};

/// AsyncRead/AsyncWrite wrapper for SSH Channels
pub struct ChannelStream<S>
where
    S: From<(ChannelId, ChannelMsg)> + Send + 'static,
{
    tx: ChannelTx<S>,
    rx: ChannelRx<ChannelCloseOnDrop<S>>,
}

impl<S> ChannelStream<S>
where
    S: From<(ChannelId, ChannelMsg)> + Send,
{
    pub(super) fn new(tx: ChannelTx<S>, rx: ChannelRx<ChannelCloseOnDrop<S>>) -> Self {
        Self { tx, rx }
    }
}

impl<S> AsyncRead for ChannelStream<S>
where
    S: From<(ChannelId, ChannelMsg)> + Send,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.rx).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for ChannelStream<S>
where
    S: From<(ChannelId, ChannelMsg)> + 'static + Send + Sync,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.tx).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.tx).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.tx).poll_shutdown(cx)
    }
}
