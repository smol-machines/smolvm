//! Options and cancellation for commands run through the embedded runtime.

use std::net::Shutdown;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::platform::uds::UdsStream;

/// How to run a command inside a machine.
#[derive(Debug, Clone, Default)]
pub struct ExecOptions {
    /// Extra environment variables.
    pub env: Vec<(String, String)>,
    /// Working directory for the command.
    pub workdir: Option<String>,
    /// Kill the command after this long.
    pub timeout: Option<Duration>,
    /// Run the command as this user: a name from the image or a numeric
    /// `uid[:gid]`. Image machines only — a bare VM's agent runs every command
    /// as root and has no per-command user, so setting this there is an error
    /// rather than a silent root.
    pub user: Option<String>,
    /// Text written to the command's stdin, which is then closed. Never
    /// stored on the guest's disk.
    pub stdin: Option<String>,
    /// Allocate a pseudo-terminal for the command (the CLI's `-t`, and the
    /// `tty` query parameter of the HTTP API's interactive exec endpoint).
    /// Only [`crate::embedded::Runtime::exec_interactive_with_options`] acts
    /// on it: the streaming and buffered variants have no channel to write
    /// input to, so they ignore it.
    pub tty: bool,
}

/// Cancels a running command from another thread.
///
/// Each command runs over its own agent connection; cancelling closes it, and
/// the guest agent kills the command (its process group, or its container on
/// an image machine) when its client disconnects. Cancelling before the command
/// starts prevents it from starting. Clones share one token.
#[derive(Debug, Clone, Default)]
pub struct ExecCancel {
    state: Arc<Mutex<CancelState>>,
}

#[derive(Debug, Default)]
struct CancelState {
    cancelled: bool,
    connection: Option<UdsStream>,
}

impl ExecCancel {
    /// A token that has not been cancelled.
    pub fn new() -> Self {
        Self::default()
    }

    /// Cancel the command: close its connection if it is running, or keep it
    /// from starting. Idempotent.
    pub fn cancel(&self) {
        let mut state = self.lock();
        state.cancelled = true;
        if let Some(connection) = state.connection.take() {
            // The command's reader is blocked on this socket; shutting it down
            // wakes that reader with EOF and tells the agent the client left.
            let _ = connection.shutdown(Shutdown::Both);
        }
    }

    /// Whether [`Self::cancel`] has been called.
    pub fn is_cancelled(&self) -> bool {
        self.lock().cancelled
    }

    /// Register the running command's connection so a later cancel can close
    /// it. Returns false (and closes it) if the token was already cancelled.
    pub(crate) fn attach(&self, connection: UdsStream) -> bool {
        let mut state = self.lock();
        if state.cancelled {
            let _ = connection.shutdown(Shutdown::Both);
            return false;
        }
        state.connection = Some(connection);
        true
    }

    /// Forget the connection once the command has finished.
    pub(crate) fn detach(&self) {
        self.lock().connection = None;
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, CancelState> {
        // A panic while holding this lock cannot leave the state inconsistent
        // (every update is a single field write), so recover from poisoning.
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    // Cancelling a running command closes its connection: a reader blocked on
    // the other end (the agent, in production) wakes with EOF.
    #[test]
    fn cancel_closes_the_attached_connection() {
        let (ours, mut peer) = UdsStream::pair().unwrap();
        let cancel = ExecCancel::new();
        assert!(cancel.attach(ours));
        let reader = std::thread::spawn(move || {
            let mut buf = [0u8; 1];
            peer.read(&mut buf).unwrap()
        });
        cancel.cancel();
        assert_eq!(reader.join().unwrap(), 0, "peer should read EOF");
        assert!(cancel.is_cancelled());
    }

    // A command cancelled before it starts never runs: attaching is refused
    // and the fresh connection is closed rather than left dangling.
    #[test]
    fn cancel_before_attach_refuses_the_command() {
        let (ours, mut peer) = UdsStream::pair().unwrap();
        let cancel = ExecCancel::new();
        cancel.cancel();
        assert!(!cancel.attach(ours));
        let mut buf = [0u8; 1];
        assert_eq!(peer.read(&mut buf).unwrap(), 0);
    }

    // Clones share one token, and cancelling again (e.g. from a drop after an
    // explicit kill) is harmless.
    #[test]
    fn cancel_is_shared_and_idempotent() {
        let cancel = ExecCancel::new();
        let clone = cancel.clone();
        clone.cancel();
        clone.cancel();
        assert!(cancel.is_cancelled());
    }

    // After the command finishes the connection is released, so a late cancel
    // (the caller lost the race) cannot touch a connection that's no longer ours.
    #[test]
    fn detach_releases_the_connection() {
        let (ours, mut peer) = UdsStream::pair().unwrap();
        let cancel = ExecCancel::new();
        assert!(cancel.attach(ours.try_clone().unwrap()));
        cancel.detach();
        cancel.cancel();
        // `ours` is still open (only the detached clone was dropped), so the
        // peer sees data we write rather than EOF.
        use std::io::Write;
        let mut ours = ours;
        ours.write_all(b"x").unwrap();
        let mut buf = [0u8; 1];
        assert_eq!(peer.read(&mut buf).unwrap(), 1);
    }
}
