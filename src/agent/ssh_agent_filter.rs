//! Host-side filter for SSH agent forwarding.
//!
//! `--ssh-agent` grants a machine the ability to list the host agent's keys and
//! ask it for signatures while the machine runs. The agent protocol carries
//! more than that: adding and removing keys, locking the agent, and vendor
//! extensions, all of which change state that outlives the machine. A raw byte
//! relay passes every one of them through, so the guest could plant a key the
//! developer's agent keeps offering after the machine is gone, or lock the
//! developer out of their own keys.
//!
//! So libkrun is not pointed at `SSH_AUTH_SOCK` directly. The boot process
//! listens on a socket in the machine's directory, reads each request frame,
//! and forwards only the two the grant covers; everything else gets
//! `SSH_AGENT_FAILURE` without reaching the agent. The filter sits on the host
//! because guest root is untrusted: it can dial the vsock port itself and skip
//! anything the guest agent does.

use crate::platform::uds::{UdsListener, UdsStream};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// `SSH_AGENTC_REQUEST_IDENTITIES`: list the agent's public keys.
const REQUEST_IDENTITIES: u8 = 11;
/// `SSH_AGENTC_SIGN_REQUEST`: sign data with one of those keys.
const SIGN_REQUEST: u8 = 13;
/// `SSH_AGENT_FAILURE`: the reply to a refused request.
const AGENT_FAILURE: u8 = 5;

/// Largest frame either side may send, OpenSSH's own limit (`AGENT_MAX_LEN`).
const MAX_FRAME: usize = 256 * 1024;

/// Connections served at once. Each costs a host thread and an agent
/// connection, and a guest must not be able to open them without bound; git
/// and ssh hold one or two.
const MAX_CONNECTIONS: usize = 32;

/// Whether a request of this type may reach the host agent.
fn is_allowed(message_type: u8) -> bool {
    matches!(message_type, REQUEST_IDENTITIES | SIGN_REQUEST)
}

/// When `upstream` (the host's `SSH_AUTH_SOCK`) is set, start the filter beside
/// `vsock_socket` and return the socket libkrun should bridge the guest to.
/// If the filter cannot start, forwarding is turned off rather than left
/// unfiltered.
pub(crate) fn guard(upstream: Option<&Path>, vsock_socket: &Path) -> Option<PathBuf> {
    let upstream = upstream?;
    let socket = vsock_socket.with_extension("ssh-agent");
    if let Err(e) = super::launcher_dynamic::check_socket_path_len(&socket) {
        tracing::warn!("SSH agent forwarding disabled: {e}");
        return None;
    }
    match start(upstream, &socket) {
        Ok(()) => Some(socket),
        Err(e) => {
            tracing::warn!(error = %e, "SSH agent forwarding disabled: the filter could not start");
            None
        }
    }
}

/// Listen on `socket` and serve each connection against `upstream`.
fn start(upstream: &Path, socket: &Path) -> io::Result<()> {
    let _ = std::fs::remove_file(socket);
    let listener = UdsListener::bind(socket)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
    }
    let upstream = upstream.to_path_buf();
    let open = Arc::new(AtomicUsize::new(0));
    std::thread::Builder::new()
        .name("ssh-agent-filter".into())
        .spawn(move || {
            for stream in listener.incoming() {
                let guest = match stream {
                    Ok(guest) => guest,
                    Err(e) => {
                        tracing::debug!(error = %e, "SSH agent filter accept failed");
                        continue;
                    }
                };
                if open.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                    open.fetch_sub(1, Ordering::SeqCst);
                    tracing::warn!("SSH agent filter: refused a connection over {MAX_CONNECTIONS}");
                    continue;
                }
                let (upstream, open) = (upstream.clone(), Arc::clone(&open));
                let spawned = std::thread::Builder::new()
                    .name("ssh-agent-filter-conn".into())
                    .spawn(move || {
                        if let Err(e) = serve(guest, &upstream) {
                            tracing::debug!(error = %e, "SSH agent filter connection ended");
                        }
                        open.fetch_sub(1, Ordering::SeqCst);
                    });
                if spawned.is_err() {
                    tracing::warn!("SSH agent filter: could not serve a connection");
                }
            }
        })?;
    Ok(())
}

/// Serve one guest connection: the agent protocol is strictly one reply per
/// request, so each allowed request is forwarded and its reply read back
/// before the next request is taken.
fn serve(mut guest: UdsStream, upstream: &Path) -> io::Result<()> {
    let mut agent = UdsStream::connect(upstream)?;
    filter(&mut guest, &mut agent)
}

/// The request loop, over any pair of streams so tests can drive it.
fn filter(guest: &mut impl ReadWrite, agent: &mut impl ReadWrite) -> io::Result<()> {
    while let Some(request) = read_frame(guest)? {
        let message_type = request.first().copied();
        if message_type.is_some_and(is_allowed) {
            write_frame(agent, &request)?;
            let Some(reply) = read_frame(agent)? else {
                return Ok(());
            };
            write_frame(guest, &reply)?;
        } else {
            tracing::info!(
                message_type = message_type.unwrap_or_default(),
                "SSH agent filter: refused a request outside list and sign"
            );
            write_frame(guest, &[AGENT_FAILURE])?;
        }
    }
    Ok(())
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

/// Read one length-prefixed frame; `None` when the peer closed between frames.
fn read_frame(stream: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut length = [0u8; 4];
    match stream.read_exact(&mut length) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("SSH agent frame of {length} bytes"),
        ));
    }
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body)?;
    Ok(Some(body))
}

fn write_frame(stream: &mut impl Write, body: &[u8]) -> io::Result<()> {
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(body);
    stream.write_all(&frame)?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stream that reads from a fixed buffer and records what is written.
    struct Scripted {
        input: io::Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl Scripted {
        fn new(frames: &[&[u8]]) -> Self {
            let mut input = Vec::new();
            for body in frames {
                write_frame(&mut input, body).unwrap();
            }
            Self {
                input: io::Cursor::new(input),
                output: Vec::new(),
            }
        }

        fn written_frames(&self) -> Vec<Vec<u8>> {
            let mut cursor = io::Cursor::new(self.output.clone());
            let mut frames = Vec::new();
            while let Some(frame) = read_frame(&mut cursor).unwrap() {
                frames.push(frame);
            }
            frames
        }
    }

    impl Read for Scripted {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.input.read(buf)
        }
    }

    impl Write for Scripted {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.output.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    const ADD_IDENTITY: u8 = 17;
    const REMOVE_IDENTITY: u8 = 18;
    const REMOVE_ALL_IDENTITIES: u8 = 19;
    const ADD_SMARTCARD_KEY: u8 = 20;
    const LOCK: u8 = 22;
    const UNLOCK: u8 = 23;
    const ADD_ID_CONSTRAINED: u8 = 25;
    const EXTENSION: u8 = 27;
    const IDENTITIES_ANSWER: u8 = 12;
    const SIGN_RESPONSE: u8 = 14;

    #[test]
    fn list_and_sign_reach_the_agent_and_their_replies_come_back() {
        let mut guest = Scripted::new(&[&[REQUEST_IDENTITIES], &[SIGN_REQUEST, 1, 2, 3]]);
        let mut agent = Scripted::new(&[&[IDENTITIES_ANSWER, 0, 0, 0, 0], &[SIGN_RESPONSE, 9]]);
        filter(&mut guest, &mut agent).unwrap();
        assert_eq!(
            agent.written_frames(),
            vec![vec![REQUEST_IDENTITIES], vec![SIGN_REQUEST, 1, 2, 3]]
        );
        assert_eq!(
            guest.written_frames(),
            vec![vec![IDENTITIES_ANSWER, 0, 0, 0, 0], vec![SIGN_RESPONSE, 9]]
        );
    }

    #[test]
    fn every_request_that_changes_the_agent_is_refused_without_reaching_it() {
        for refused in [
            ADD_IDENTITY,
            REMOVE_IDENTITY,
            REMOVE_ALL_IDENTITIES,
            ADD_SMARTCARD_KEY,
            LOCK,
            UNLOCK,
            ADD_ID_CONSTRAINED,
            EXTENSION,
            1, // protocol 1 REQUEST_RSA_IDENTITIES
            255,
        ] {
            let mut guest = Scripted::new(&[&[refused, 7, 7]]);
            let mut agent = Scripted::new(&[]);
            filter(&mut guest, &mut agent).unwrap();
            assert!(agent.output.is_empty(), "type {refused} reached the agent");
            assert_eq!(guest.written_frames(), vec![vec![AGENT_FAILURE]]);
        }
    }

    #[test]
    fn a_refusal_does_not_end_the_connection() {
        let mut guest = Scripted::new(&[&[ADD_IDENTITY], &[REQUEST_IDENTITIES]]);
        let mut agent = Scripted::new(&[&[IDENTITIES_ANSWER, 0, 0, 0, 0]]);
        filter(&mut guest, &mut agent).unwrap();
        assert_eq!(agent.written_frames(), vec![vec![REQUEST_IDENTITIES]]);
        assert_eq!(
            guest.written_frames(),
            vec![vec![AGENT_FAILURE], vec![IDENTITIES_ANSWER, 0, 0, 0, 0]]
        );
    }

    #[test]
    fn an_oversized_or_empty_frame_ends_the_connection() {
        for length in [0u32, (MAX_FRAME + 1) as u32] {
            let mut guest = Scripted {
                input: io::Cursor::new(length.to_be_bytes().to_vec()),
                output: Vec::new(),
            };
            let mut agent = Scripted::new(&[]);
            assert!(filter(&mut guest, &mut agent).is_err());
            assert!(agent.output.is_empty());
        }
    }
}
