//! Shutdown transport; completion is distinct from a liveness heartbeat.

use smolvm_protocol::{error_codes, AgentResponse};
use std::io::{self, Write};
use std::time::Duration;

pub fn respond(
    stream: &mut crate::WireStream<impl Write>,
    progress: bool,
    operation: impl FnOnce() -> io::Result<()> + Send,
) -> Result<(), Box<dyn std::error::Error>> {
    respond_with_interval(stream, progress, operation, Duration::from_secs(1))
}

fn respond_with_interval(
    stream: &mut crate::WireStream<impl Write>,
    progress: bool,
    operation: impl FnOnce() -> io::Result<()> + Send,
    interval: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = std::thread::scope(|scope| {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("shutdown-storage".into())
            .spawn_scoped(scope, move || {
                let _ = tx.send(operation());
            })?;
        let mut connected = true;
        loop {
            match rx.recv_timeout(interval) {
                Ok(result) => return result,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(io::Error::other("storage synchronization worker stopped"));
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if progress && connected {
                        connected = super::send_response(
                            stream,
                            &AgentResponse::Progress {
                                message: "waiting for storage synchronization".into(),
                                percent: None,
                                layer: None,
                            },
                        )
                        .is_ok();
                    }
                    // A disconnected caller must not interrupt a disk flush.
                }
            }
        }
    });
    let response = match result {
        Ok(()) => AgentResponse::ok(Some(serde_json::json!({
            "shutdown": true,
            "filesystems_quiesced": true,
        }))),
        Err(error) => AgentResponse::error(error.to_string(), error_codes::INTERNAL_ERROR),
    };
    super::send_response(stream, &response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    fn frames(mut bytes: &[u8]) -> Vec<AgentResponse> {
        let mut out = Vec::new();
        while !bytes.is_empty() {
            let len = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
            out.push(serde_json::from_slice(&bytes[4..4 + len]).unwrap());
            bytes = &bytes[4 + len..];
        }
        out
    }

    #[test]
    fn legacy_shutdown_receives_only_final_ack() {
        let mut out = Vec::new();
        respond_with_interval(
            &mut crate::WireStream::new(&mut out),
            false,
            || Ok(()),
            Duration::from_millis(1),
        )
        .unwrap();
        assert!(matches!(
            frames(&out).as_slice(),
            [AgentResponse::Ok { .. }]
        ));
        let decoded = frames(&out);
        assert!(matches!(
            &decoded[0],
            AgentResponse::Ok { data: Some(data) }
                if data["filesystems_quiesced"] == true
        ));
    }

    #[test]
    fn failed_flush_never_emits_success() {
        let mut out = Vec::new();
        respond(&mut crate::WireStream::new(&mut out), true, || {
            Err(io::Error::other("flush failed"))
        })
        .unwrap();
        assert!(
            matches!(frames(&out).as_slice(), [AgentResponse::Error { message, .. }] if message == "flush failed")
        );
    }

    #[test]
    fn disconnected_caller_does_not_cancel_flush() {
        struct Disconnected;
        impl Write for Disconnected {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "disconnected"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let complete = std::sync::atomic::AtomicBool::new(false);
        assert!(
            respond(&mut crate::WireStream::new(&mut Disconnected), true, || {
                complete.store(true, std::sync::atomic::Ordering::Release);
                Ok(())
            })
            .is_err()
        );
        assert!(complete.load(std::sync::atomic::Ordering::Acquire));
    }

    #[test]
    fn progress_precedes_completion_and_does_not_ack_early() {
        struct ObservedWriter {
            bytes: Vec<u8>,
            signal: Option<mpsc::Sender<()>>,
        }
        impl Write for ObservedWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.bytes.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                if let Some(signal) = self.signal.take() {
                    assert!(matches!(
                        frames(&self.bytes).as_slice(),
                        [AgentResponse::Progress { .. }]
                    ));
                    signal.send(()).unwrap();
                }
                Ok(())
            }
        }
        let (tx, rx) = mpsc::channel();
        let mut out = ObservedWriter {
            bytes: Vec::new(),
            signal: Some(tx),
        };
        respond_with_interval(
            &mut crate::WireStream::new(&mut out),
            true,
            move || {
                rx.recv_timeout(Duration::from_secs(3))
                    .map_err(io::Error::other)?;
                Ok(())
            },
            Duration::from_millis(1),
        )
        .unwrap();
        let decoded = frames(&out.bytes);
        assert!(matches!(
            decoded.first(),
            Some(AgentResponse::Progress { .. })
        ));
        assert!(matches!(decoded.last(), Some(AgentResponse::Ok { .. })));
        assert!(matches!(
            decoded.last(),
            Some(AgentResponse::Ok { data: Some(data) })
                if data["filesystems_quiesced"] == true
        ));
    }
}
