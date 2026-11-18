//! Independently addressable controls for one connection-owned VM command.
use serde::{Deserialize, Serialize};

/// The agent supports controlled VM exec and a separate signal/resize connection.
pub const CAPABILITY: &str = "vm-exec-control-v1";

/// An interactive VM command whose controls do not share its stdin stream.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Session {
    /// Caller-generated, unique 128-bit identifier, encoded as 32 lowercase hex digits.
    pub id: String,
    /// Program and arguments; executed inside the VM.
    pub command: Vec<String>,
    /// Guest environment overrides.
    #[serde(default)]
    pub env: Vec<(String, String)>,
    /// Guest working directory.
    pub workdir: Option<String>,
    /// Command lifetime limit in milliseconds.
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    /// Allocate a terminal rather than byte-preserving pipes.
    #[serde(default)]
    pub tty: bool,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("tty", &self.tty)
            .finish_non_exhaustive()
    }
}

/// A control request sent on a separate agent connection.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// Identifier of the still-running session.
    pub id: String,
    /// Operation to perform on its owned process or terminal.
    pub action: Action,
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("action", &self.action)
            .finish_non_exhaustive()
    }
}

/// Linux signal or terminal resize, independent of blocked command I/O.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    /// Signal the command's process group; signal numbers are Linux values.
    Signal {
        /// Linux signal number, from 1 through 64.
        signal: u8,
    },
    /// Set terminal dimensions in character cells.
    Resize {
        /// Nonzero terminal width in character cells.
        cols: u16,
        /// Nonzero terminal height in character cells.
        rows: u16,
    },
}

/// Validate the bounded session namespace without interpreting filesystem paths.
pub fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identifiers_and_payloads_are_not_exposed_in_diagnostics() {
        let session = Session {
            id: "abcdef0123456789abcdef0123456789".into(),
            command: vec!["secret-command".into()],
            env: vec![("TOKEN".into(), "secret-env".into())],
            workdir: Some("private-path".into()),
            timeout_ms: None,
            tty: false,
        };
        let request = Request {
            id: session.id.clone(),
            action: Action::Signal { signal: 2 },
        };
        let diagnostic = format!("{session:?} {request:?}");
        for hidden in [
            &session.id,
            &session.command[0],
            &session.env[0].1,
            session.workdir.as_ref().unwrap(),
        ] {
            assert!(!diagnostic.contains(hidden));
        }
        assert!(valid_id(&session.id));
        for bad in [
            "",
            "../../tmp/control",
            "ABCDEF0123456789abcdef0123456789",
            "abcdef0123456789abcdef01234567890",
        ] {
            assert!(!valid_id(bad));
        }
        let encoded = serde_json::to_vec(&request).unwrap();
        assert_eq!(
            serde_json::from_slice::<Request>(&encoded).unwrap().id,
            request.id
        );
    }
}
