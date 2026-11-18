use super::*;
use std::{io, time::Duration};
use tokio::sync::{mpsc, oneshot};

fn connection() -> (AgentReader, AgentWriter, UnixStream) {
    let (host, guest) = UnixStream::pair().unwrap();
    let (read, write) = host.into_split();
    let binary = Arc::new(AtomicBool::new(false));
    (
        AgentReader(read, binary.clone()),
        AgentWriter(write, binary),
        guest,
    )
}

async fn response<W: tokio::io::AsyncWrite + Unpin>(
    guest: &mut W,
    response: AgentResponse,
    binary: bool,
) {
    let mut bytes = Vec::new();
    if !binary || !smolvm_protocol::binary_stream::write_response(&mut bytes, &response).unwrap() {
        bytes = smolvm_protocol::encode_message(&smolvm_protocol::Envelope::new(response)).unwrap();
    }
    guest.write_all(&bytes).await.unwrap();
}

#[tokio::test]
async fn blocked_output_keeps_stdin_live_and_detachment_retains_real_exit() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (reader, writer, guest) = connection();
        let queue = Arc::new(InputQueue::default());
        let input = queue.sender();
        let (tx, rx) = mpsc::channel(1);
        let (blocked, waiting) = oneshot::channel();
        let mut blocked = Some(blocked);
        let pump = tokio::spawn(async move {
            pump(reader, writer, &queue, move |stream, data| {
                if tx.capacity() == 0 {
                    if let Some(blocked) = blocked.take() {
                        blocked.send(()).unwrap();
                    }
                }
                let tx = tx.clone();
                async move {
                    let _ = tx.send((stream, data)).await;
                }
            })
            .await
        });
        let (mut guest_read, mut guest_write) = guest.into_split();
        let output = tokio::spawn(async move {
            // More than the socket and application queues can hold together.
            for _ in 0..128 {
                response(
                    &mut guest_write,
                    AgentResponse::Stdout {
                        data: vec![42; OUTPUT_CHUNK],
                    },
                    true,
                )
                .await;
            }
            response(
                &mut guest_write,
                AgentResponse::Exited {
                    exit_code: 23,
                    oom: false,
                },
                false,
            )
            .await;
        });
        waiting.await.unwrap();
        input
            .send(Input::Data(b"still interactive".to_vec()))
            .await
            .unwrap();
        input.send(Input::Eof).await.unwrap();
        for expected in [b"still interactive".as_slice(), b""] {
            let len = guest_read.read_u32().await.unwrap();
            let mut body = vec![0; len as usize];
            guest_read.read_exact(&mut body).await.unwrap();
            let request = smolvm_protocol::binary_stream::decode_request(&body).unwrap();
            assert!(matches!(request.body, AgentRequest::Stdin { data } if data == expected));
        }
        assert!(!pump.is_finished(), "output must wait for capacity");
        assert!(
            !output.is_finished(),
            "backpressure must reach the guest socket"
        );
        drop(rx); // A detached client must release the blocked sender.
        let exit = pump.await.unwrap().unwrap();
        assert_eq!(exit.code, 23);
        assert!(!exit.oom);
        output.await.unwrap();
    })
    .await
    .expect("blocked output prevented input or exit progress");
}

#[tokio::test]
async fn legacy_output_and_large_binary_frames_preserve_bytes_and_streams() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (reader, writer, mut guest) = connection();
        let output = tokio::spawn(async move {
            response(
                &mut guest,
                AgentResponse::Stdout {
                    data: vec![255; OUTPUT_CHUNK],
                },
                false,
            )
            .await;
            response(
                &mut guest,
                AgentResponse::Stderr {
                    data: vec![17; OUTPUT_CHUNK * 3 + 7],
                },
                true,
            )
            .await;
            response(
                &mut guest,
                AgentResponse::Exited {
                    exit_code: 73,
                    oom: true,
                },
                false,
            )
            .await;
        });
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = pump(reader, writer, &InputQueue::default(), |stream, data| {
            assert!(data.len() <= OUTPUT_CHUNK);
            if stream == 1 {
                stdout.extend(data);
            } else {
                stderr.extend(data);
            }
            std::future::ready(())
        })
        .await
        .unwrap();
        assert_eq!(stdout, vec![255; OUTPUT_CHUNK]);
        assert_eq!(stderr, vec![17; OUTPUT_CHUNK * 3 + 7]);
        assert_eq!(exit.code, 73);
        assert!(exit.oom);
        output.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn lost_transport_is_not_a_process_exit_or_synthetic_stderr() {
    let (reader, writer, guest) = connection();
    drop(guest);
    let result = pump(reader, writer, &InputQueue::default(), |_, _| {
        panic!("transport diagnostics must not corrupt process output");
        #[allow(unreachable_code)]
        std::future::ready(())
    })
    .await;
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
}

#[tokio::test]
async fn stream_frame_limit_rejects_a_header_without_waiting_for_its_body() {
    let (reader, writer, mut guest) = connection();
    guest
        .write_u32((STREAM_FRAME_LIMIT + 1) as u32)
        .await
        .unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        pump(reader, writer, &InputQueue::default(), |_, _| async {}),
    )
    .await
    .unwrap();
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
}

#[tokio::test]
async fn guest_error_is_not_invented_as_a_process_exit() {
    let (reader, writer, mut guest) = connection();
    response(
        &mut guest,
        AgentResponse::Error {
            message: "exec owner disappeared".into(),
            code: None,
        },
        false,
    )
    .await;
    let result = pump(reader, writer, &InputQueue::default(), |_, _| async {}).await;
    assert_eq!(result.unwrap_err().to_string(), "exec owner disappeared");
}
