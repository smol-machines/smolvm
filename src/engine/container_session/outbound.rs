use super::*;
#[derive(Default)]
struct Pending {
    input: Option<(u64, wire::Input)>,
    ack: Option<u64>,
}
/// One pending input and a coalesced output acknowledgement, never one queued
/// ACK per chunk. The writer and reader make progress independently.
#[derive(Default)]
pub(super) struct Outbound {
    pending: parking_lot::Mutex<Pending>,
    wake: tokio::sync::Notify,
}
impl Outbound {
    pub fn input(&self, sequence: u64, input: wire::Input) {
        let mut pending = self.pending.lock();
        debug_assert!(pending.input.is_none());
        pending.input = Some((sequence, input));
        self.wake.notify_one();
    }
    pub fn ack(&self, next: u64) {
        self.pending.lock().ack = Some(next);
        self.wake.notify_one();
    }
    pub async fn send(&self, mut writer: AgentWriter) -> io::Error {
        loop {
            let notified = self.wake.notified();
            let control = {
                let mut pending = self.pending.lock();
                if let Some((sequence, input)) = pending.input.take() {
                    Some(Control::Input { sequence, input })
                } else {
                    pending.ack.take().map(|next| Control::OutputAck { next })
                }
            };
            match control {
                Some(control) => {
                    if let Err(error) = writer
                        .send(&AgentRequest::ContainerSession { control })
                        .await
                    {
                        return error;
                    }
                }
                None => notified.await,
            }
        }
    }
}
