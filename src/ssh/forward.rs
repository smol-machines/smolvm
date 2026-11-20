//! Translate the guest TCP helper's bounded frames into SSH channel events.
use crate::agent::InteractiveOutput;
use anyhow::{Context, Result};
use russh::{server, ChannelOpenFailure, ChannelWriteHalf};
use smolvm_protocol::tcp_forward::{Decoder, Event};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::sync::mpsc;

pub(super) async fn output(
    mut receiver: mpsc::Receiver<InteractiveOutput>,
    writer: Arc<ChannelWriteHalf<server::Msg>>,
    reply: server::ChannelOpenHandle,
    accepted: Arc<AtomicBool>,
) -> Result<()> {
    let mut reply = Some(reply);
    let mut decoder = Decoder::default();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let result = async {
        loop {
            let next = if reply.is_some() {
                tokio::time::timeout_at(deadline, receiver.recv())
                    .await
                    .context("guest TCP connection timed out")?
            } else {
                receiver.recv().await
            };
            let Some(chunk) = next else {
                break;
            };
            let InteractiveOutput::Stdout(bytes) = chunk else {
                anyhow::bail!("guest TCP connection failed");
            };
            let mut bytes = bytes.as_slice();
            while !bytes.is_empty() {
                match decoder.consume(&mut bytes).map_err(anyhow::Error::msg)? {
                    Some(Event::Connected) => {
                        reply
                            .take()
                            .context("duplicate TCP connection acknowledgement")?
                            .accept()
                            .await;
                        accepted.store(true, Ordering::SeqCst);
                    }
                    Some(Event::Data(bytes)) => writer.data_bytes(bytes).await?,
                    Some(Event::Eof) => writer.eof().await?,
                    None => (),
                }
            }
        }
        decoder.finish().map_err(anyhow::Error::msg)
    }
    .await;
    if let Some(reply) = reply {
        reply.reject(ChannelOpenFailure::ConnectFailed).await;
    }
    result
}
