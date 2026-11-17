//! Commands the node owns: execs that outlive the connection that started them.
//!
//! A plain exec lives in one HTTP request: the node streams the command's
//! output into that request and nothing else can see it. A proxy in between
//! (the control plane) that restarts takes the command's output, and its exit
//! code, with it. An exec session instead belongs to the node:
//!
//! - It has an id, chosen by the client so that a retried start is the same
//!   start (`POST .../execs` with an id the node already has answers with that
//!   session instead of running the command again; an id that ran and was
//!   collected is refused for [`TOMBSTONE_TTL`]).
//! - The node keeps the process and its connection to the guest agent. Output
//!   goes into a buffer addressed by byte offset: stdout and stderr share one
//!   offset space, and each chunk says which stream it came from.
//! - A reader asks for output `after` an offset. Asking for `after = N` is also
//!   the reader's acknowledgement that it holds every byte before N, so the
//!   node drops those. Asking again with the same offset (an answer lost on the
//!   way) returns the same bytes, so a client that only ever advances to the
//!   `next` it was given sees every byte exactly once.
//! - The buffer is bounded (the output *window*, 8 MiB by default). While a
//!   client is following the command, the command may run at most one window
//!   ahead of what the client acknowledged; past that the node stops reading
//!   its output, which blocks the command's writes exactly as a slow pipe
//!   reader would. Nothing is dropped.
//! - The rule when a client falls too far behind: once nobody has read the
//!   session for the detach grace (120 s by default), the command is no longer
//!   held back. The node keeps only the newest window of output, and a client
//!   that comes back later is told exactly which offsets it lost (`lost`), then
//!   continues from the oldest byte still held. An interactive session (stdin
//!   from the client) is killed instead, as closing an interactive exec always
//!   did: nobody can type into it any more.
//! - The exit status is kept until a reader has been handed it and a short
//!   grace has passed ([`COLLECTED_TTL`], so an answer lost in flight can be
//!   asked for again), or until the exit TTL passes unread (10 min by default),
//!   or until the client deletes the session.
//! - Stdin carries sequence numbers: frame `n` is applied only if frame `n - 1`
//!   was, a resent frame the node already applied is acknowledged and ignored,
//!   and every answer says the last frame applied, so a client resends exactly
//!   what is missing after a reconnect. One frame is at most
//!   [`MAX_STDIN_FRAME`] bytes, which the node applies whole or not at all.
//!
//! Nothing about a running session lives in the proxy, so any control plane can
//! serve any read given the machine, the exec id and the last offset.

use crate::agent::{InteractiveInput, InteractiveInputSender, InteractiveOutput};
use axum::body::Bytes;
use parking_lot::{Condvar, Mutex};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

/// Largest stdin frame: one frame is one message to the agent, so it is
/// applied whole or not at all.
pub const MAX_STDIN_FRAME: usize = 64 * 1024;

/// How long a session whose exit a reader was handed stays, so a reader whose
/// answer was lost on the way can ask again.
pub const COLLECTED_TTL: Duration = Duration::from_secs(60);

/// How long the id of a deleted or expired session is refused, so a start
/// retried that late cannot run the command a second time.
pub const TOMBSTONE_TTL: Duration = Duration::from_secs(3600);

/// Longest a read may wait for new output.
pub const MAX_WAIT: Duration = Duration::from_secs(60);

/// How long a waiting read lingers after output arrives, for more or the exit.
const OUTPUT_LINGER: Duration = Duration::from_millis(20);

/// A waiting reader that comes back sooner than this for less than
/// [`PACE_BATCH`] bytes is held until this much time has passed since its last
/// read: a chatty command is then read in at most ten answers a second, in
/// larger pieces, instead of one per round trip.
const PACE: Duration = Duration::from_millis(100);

/// Output enough to answer a paced reader at once.
const PACE_BATCH: u64 = 256 * 1024;

/// Most sessions one node holds, running or not yet collected.
pub const MAX_SESSIONS: usize = 4096;

/// Most sessions one machine holds.
pub const MAX_SESSIONS_PER_MACHINE: usize = 512;

/// The tunables, from the environment once.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Output held per session, and how far a followed command may run ahead
    /// of its reader (`SMOLVM_EXEC_OUTPUT_WINDOW_BYTES`).
    pub window: usize,
    /// How long a session may go unread before it is no longer held back, or,
    /// interactive, is killed (`SMOLVM_EXEC_DETACH_GRACE_SECS`).
    pub detach_grace: Duration,
    /// How long an exit nobody read is kept (`SMOLVM_EXEC_EXIT_TTL_SECS`).
    pub exit_ttl: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            window: 8 * 1024 * 1024,
            detach_grace: Duration::from_secs(120),
            exit_ttl: Duration::from_secs(600),
        }
    }
}

impl Limits {
    fn from_env() -> Self {
        let get = |k: &str| {
            std::env::var(k)
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())
        };
        let d = Self::default();
        Self {
            window: get("SMOLVM_EXEC_OUTPUT_WINDOW_BYTES")
                .map(|v| (v as usize).max(64 * 1024))
                .unwrap_or(d.window),
            detach_grace: get("SMOLVM_EXEC_DETACH_GRACE_SECS")
                .map(Duration::from_secs)
                .unwrap_or(d.detach_grace),
            exit_ttl: get("SMOLVM_EXEC_EXIT_TTL_SECS")
                .map(Duration::from_secs)
                .unwrap_or(d.exit_ttl),
        }
    }
}

/// Which output stream a chunk came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputStream {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
}

impl OutputStream {
    /// The byte that names the stream in an attach frame.
    pub fn tag(self) -> u8 {
        match self {
            OutputStream::Stdout => 1,
            OutputStream::Stderr => 2,
        }
    }
}

#[derive(Debug, Clone)]
struct Chunk {
    offset: u64,
    stream: OutputStream,
    data: Bytes,
}

impl Chunk {
    fn end(&self) -> u64 {
        self.offset + self.data.len() as u64
    }
}

/// How a session ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exit {
    /// The command's exit code, when it exited.
    pub code: Option<i32>,
    /// Why there is no exit code, or what went wrong around it.
    pub error: Option<String>,
}

/// Where a session is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionState {
    /// Accepted; the command is being started.
    Starting,
    /// The command is running.
    Running,
    /// The command ended (see [`Exit`]).
    Exited,
}

/// A piece of output handed to a reader.
#[derive(Debug, Clone)]
pub struct OutputPiece {
    /// The stream it came from.
    pub stream: OutputStream,
    /// Offset of its first byte.
    pub offset: u64,
    /// The bytes.
    pub data: Bytes,
}

/// What one read returns.
#[derive(Debug, Clone)]
pub struct Batch {
    /// The output, in offset order.
    pub output: Vec<OutputPiece>,
    /// The offset to read after next.
    pub next: u64,
    /// The oldest offset still held.
    pub start: u64,
    /// One past the newest byte produced.
    pub end: u64,
    /// Offsets the reader asked for that are no longer held (from, to).
    pub lost: Option<(u64, u64)>,
    /// Where the session is.
    pub state: SessionState,
    /// How it ended, once it has.
    pub exit: Option<Exit>,
    /// The command ended and this batch reaches the end of its output.
    pub done: bool,
    /// The last stdin frame applied (0 = none).
    pub stdin_applied: u64,
}

/// Why a stdin frame was not applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StdinError {
    /// A frame before this one is missing; resend from `applied + 1`.
    Gap {
        /// The last frame applied.
        applied: u64,
    },
    /// Stdin was closed (end of input sent, or the command ended).
    Closed {
        /// The last frame applied.
        applied: u64,
    },
    /// The command did not take its input in time; nothing was applied.
    Busy {
        /// The last frame applied.
        applied: u64,
    },
    /// The frame is larger than [`MAX_STDIN_FRAME`].
    TooLarge,
    /// The session takes no stdin.
    NotInteractive,
}

struct Inner {
    state: SessionState,
    chunks: VecDeque<Chunk>,
    /// Oldest offset held.
    floor: u64,
    /// One past the newest byte produced.
    end: u64,
    /// Every byte before this was acknowledged by a reader.
    acked: u64,
    /// Last time a reader asked for output (or was attached).
    last_access: Instant,
    /// Readers attached over a WebSocket right now.
    attached: usize,
    /// When a reader last read (paces readers that come straight back).
    last_read: Option<Instant>,
    exit: Option<Exit>,
    exited_at: Option<Instant>,
    /// When a reader was handed the exit.
    collected_at: Option<Instant>,
    stdin_applied: u64,
    stdin_closed: bool,
    killed: bool,
}

/// What a start request asked for, to tell a retried start from a different
/// command reusing the id.
pub type Fingerprint = u64;

/// One exec the node owns.
pub struct ExecSession {
    /// The exec id.
    pub id: String,
    /// The machine it runs in.
    pub machine: String,
    /// The command and its arguments.
    pub command: Vec<String>,
    /// It runs on a PTY.
    pub tty: bool,
    /// Its stdin takes sequenced frames.
    pub interactive: bool,
    /// When it was started.
    pub created_at: SystemTime,
    fingerprint: Fingerprint,
    limits: Limits,
    inner: Mutex<Inner>,
    /// Wakes a producer held back by an unacknowledged window.
    acked_cv: Condvar,
    /// Bumped whenever output, the exit, or the state changes.
    changed: tokio::sync::watch::Sender<u64>,
    /// The command's input. Held for the session's life: dropping it is how a
    /// session is killed (the agent kills the command when its connection
    /// closes). Locked across a stdin frame so frames apply in order.
    input: tokio::sync::Mutex<Option<InteractiveInputSender>>,
}

impl ExecSession {
    fn new(
        id: String,
        machine: String,
        command: Vec<String>,
        tty: bool,
        interactive: bool,
        fingerprint: Fingerprint,
        limits: Limits,
    ) -> Self {
        Self {
            id,
            machine,
            command,
            tty,
            interactive,
            created_at: SystemTime::now(),
            fingerprint,
            limits,
            inner: Mutex::new(Inner {
                state: SessionState::Starting,
                chunks: VecDeque::new(),
                floor: 0,
                end: 0,
                acked: 0,
                last_access: Instant::now(),
                attached: 0,
                last_read: None,
                exit: None,
                exited_at: None,
                collected_at: None,
                stdin_applied: 0,
                stdin_closed: !interactive,
                killed: false,
            }),
            acked_cv: Condvar::new(),
            changed: tokio::sync::watch::channel(0).0,
            input: tokio::sync::Mutex::new(None),
        }
    }

    fn bump(&self) {
        self.changed.send_modify(|v| *v = v.wrapping_add(1));
    }

    /// The session's current state.
    pub fn state(&self) -> SessionState {
        self.inner.lock().state
    }

    /// How the session ended, once it has.
    pub fn exit(&self) -> Option<Exit> {
        self.inner.lock().exit.clone()
    }

    /// Hand the session its input channel (before the command starts).
    pub async fn set_input(&self, tx: InteractiveInputSender) {
        *self.input.lock().await = Some(tx);
    }

    /// The command is running.
    pub fn mark_running(&self) {
        let mut inner = self.inner.lock();
        if inner.state == SessionState::Starting {
            inner.state = SessionState::Running;
        }
        drop(inner);
        self.bump();
    }

    /// The command ended. A second call (a kill racing the exit) keeps the first.
    pub fn finish(&self, exit: Exit) {
        let mut inner = self.inner.lock();
        if inner.exit.is_none() {
            inner.exit = Some(exit);
            inner.exited_at = Some(Instant::now());
        }
        inner.state = SessionState::Exited;
        inner.stdin_closed = true;
        drop(inner);
        self.acked_cv.notify_all();
        self.bump();
    }

    /// Append output from the command, waiting while a followed reader is a
    /// window behind. Called from the blocking thread that runs the session.
    pub fn push_output(&self, stream: OutputStream, data: Vec<u8>) {
        if data.is_empty() {
            return;
        }
        let window = self.limits.window as u64;
        let mut inner = self.inner.lock();
        loop {
            if inner.killed {
                return;
            }
            let unread = inner.end - inner.acked;
            if unread < window || self.detached(&inner) {
                break;
            }
            self.acked_cv
                .wait_for(&mut inner, Duration::from_millis(250));
        }
        let offset = inner.end;
        inner.end += data.len() as u64;
        inner.chunks.push_back(Chunk {
            offset,
            stream,
            data: Bytes::from(data),
        });
        self.trim(&mut inner);
        drop(inner);
        self.bump();
    }

    /// Nobody has read the session for the detach grace.
    fn detached(&self, inner: &Inner) -> bool {
        inner.attached == 0 && inner.last_access.elapsed() >= self.limits.detach_grace
    }

    /// Drop what is no longer needed: bytes a reader acknowledged and, once the
    /// session is detached, anything older than the newest window.
    fn trim(&self, inner: &mut Inner) {
        while inner.chunks.front().is_some_and(|c| c.end() <= inner.acked) {
            inner.chunks.pop_front();
        }
        if self.detached(inner) {
            let keep_from = inner.end.saturating_sub(self.limits.window as u64);
            while let Some(front) = inner.chunks.front_mut() {
                if front.end() <= keep_from {
                    inner.chunks.pop_front();
                } else if front.offset < keep_from {
                    let cut = (keep_from - front.offset) as usize;
                    front.data = front.data.slice(cut..);
                    front.offset = keep_from;
                    break;
                } else {
                    break;
                }
            }
        }
        inner.floor = inner.chunks.front().map(|c| c.offset).unwrap_or(inner.end);
    }

    /// A reader holds every byte before `offset`.
    pub fn ack(&self, offset: u64) {
        let mut inner = self.inner.lock();
        let offset = offset.min(inner.end);
        if offset > inner.acked {
            inner.acked = offset;
            self.trim(&mut inner);
            drop(inner);
            self.acked_cv.notify_all();
        }
    }

    /// Note that a reader is here (it keeps a followed command held back
    /// rather than detached).
    pub fn touch(&self) {
        self.inner.lock().last_access = Instant::now();
    }

    /// A WebSocket reader attached; the returned guard detaches it.
    pub fn attach(self: &Arc<Self>) -> AttachGuard {
        let mut inner = self.inner.lock();
        inner.attached += 1;
        inner.last_access = Instant::now();
        AttachGuard(self.clone())
    }

    /// Output after `after`, at most `max` bytes. With `ack`, `after` also
    /// acknowledges everything before it (a polling reader); an attached
    /// reader acknowledges separately, since what was sent is not yet what it
    /// received. Errors when `after` is beyond the newest byte.
    pub fn read(&self, after: u64, max: usize, ack: bool) -> Result<Batch, u64> {
        if ack {
            self.ack(after);
        }
        let mut inner = self.inner.lock();
        if after > inner.end {
            return Err(inner.end);
        }
        inner.last_access = Instant::now();
        if ack {
            inner.last_read = Some(Instant::now());
        }
        let mut pos = after;
        let mut lost = None;
        if pos < inner.floor {
            lost = Some((pos, inner.floor));
            pos = inner.floor;
        }
        let mut output = Vec::new();
        let mut budget = max.max(1);
        for chunk in inner.chunks.iter() {
            if budget == 0 {
                break;
            }
            if chunk.end() <= pos {
                continue;
            }
            let skip = pos.saturating_sub(chunk.offset) as usize;
            let take = (chunk.data.len() - skip).min(budget);
            output.push(OutputPiece {
                stream: chunk.stream,
                offset: chunk.offset + skip as u64,
                data: chunk.data.slice(skip..skip + take),
            });
            pos += take as u64;
            budget -= take;
        }
        let done = inner.exit.is_some() && pos == inner.end;
        if done && inner.collected_at.is_none() {
            inner.collected_at = Some(Instant::now());
        }
        Ok(Batch {
            output,
            next: pos,
            start: inner.floor,
            end: inner.end,
            lost,
            state: inner.state,
            exit: inner.exit.clone(),
            done,
            stdin_applied: inner.stdin_applied,
        })
    }

    /// Wait until there is output after `after`, the session ended, or `wait`
    /// passed.
    pub async fn wait_for_output(&self, after: u64, wait: Duration) {
        let mut rx = self.changed.subscribe();
        let deadline = tokio::time::Instant::now() + wait.min(MAX_WAIT);
        let mut waited = false;
        loop {
            {
                let mut inner = self.inner.lock();
                inner.last_access = Instant::now();
                if inner.exit.is_some() {
                    return;
                }
                if after < inner.end || after < inner.floor {
                    break;
                }
            }
            waited = true;
            match tokio::time::timeout_at(deadline, rx.changed()).await {
                Ok(Ok(())) => continue,
                _ => {
                    self.touch();
                    return;
                }
            }
        }
        if !waited {
            return;
        }
        // Output just arrived: give the command a moment to write more or to
        // exit, so a short command's whole run fits one answer and a chatty
        // one is read in fewer, larger pieces.
        let linger = tokio::time::Instant::now() + OUTPUT_LINGER;
        while self.exit().is_none() {
            if !matches!(
                tokio::time::timeout_at(linger, rx.changed()).await,
                Ok(Ok(()))
            ) {
                break;
            }
        }
    }

    /// Hold a reader that came straight back for a little output (see
    /// [`PACE`]) until the pace allows, more output is waiting, or the
    /// command ended.
    pub async fn pace(&self, after: u64) {
        let deadline = {
            let inner = self.inner.lock();
            match inner.last_read {
                Some(t) if t.elapsed() < PACE => tokio::time::Instant::now() + (PACE - t.elapsed()),
                _ => return,
            }
        };
        let mut rx = self.changed.subscribe();
        loop {
            {
                let inner = self.inner.lock();
                if inner.exit.is_some() || inner.end.saturating_sub(after) >= PACE_BATCH {
                    return;
                }
            }
            if !matches!(
                tokio::time::timeout_at(deadline, rx.changed()).await,
                Ok(Ok(()))
            ) {
                return;
            }
        }
    }

    /// Apply stdin frame `seq` (the first frame is 1). Returns the last frame
    /// applied: `seq` itself, or a later one when this was a resend.
    pub async fn apply_stdin(&self, seq: u64, data: &[u8], eof: bool) -> Result<u64, StdinError> {
        if !self.interactive {
            return Err(StdinError::NotInteractive);
        }
        if data.len() > MAX_STDIN_FRAME {
            return Err(StdinError::TooLarge);
        }
        let input = self.input.lock().await;
        let (applied, closed) = {
            let mut inner = self.inner.lock();
            inner.last_access = Instant::now();
            (inner.stdin_applied, inner.stdin_closed)
        };
        if seq <= applied {
            return Ok(applied);
        }
        if closed {
            return Err(StdinError::Closed { applied });
        }
        if seq != applied + 1 {
            return Err(StdinError::Gap { applied });
        }
        let Some(tx) = input.as_ref() else {
            return Err(StdinError::Closed { applied });
        };
        let send = |event| tokio::time::timeout(Duration::from_secs(30), tx.send(event));
        if !data.is_empty() {
            match send(InteractiveInput::Stdin(data.to_vec())).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => return Err(StdinError::Closed { applied }),
                Err(_) => return Err(StdinError::Busy { applied }),
            }
        }
        if eof {
            // The data (if any) is in; the end of input follows it. Should the
            // end of input not fit now, the frame still counts as applied for
            // its data, and the input is closed once the queue takes it.
            if !matches!(send(InteractiveInput::Eof).await, Ok(Ok(()))) {
                tracing::debug!(exec = %self.id, "exec session: end of input not queued");
            }
        }
        let mut inner = self.inner.lock();
        inner.stdin_applied = seq;
        if eof {
            inner.stdin_closed = true;
        }
        Ok(seq)
    }

    /// Feed input that came with the start request (not sequenced), and close
    /// stdin for a session that takes no more.
    pub async fn apply_initial_stdin(&self, data: Option<Vec<u8>>) {
        let input = self.input.lock().await;
        let Some(tx) = input.as_ref() else { return };
        if let Some(data) = data {
            for chunk in data.chunks(MAX_STDIN_FRAME) {
                if tx
                    .send(InteractiveInput::Stdin(chunk.to_vec()))
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }
        if !self.interactive {
            let _ = tx.send(InteractiveInput::Eof).await;
        }
    }

    /// Resize the terminal (a TTY session only).
    pub async fn resize(&self, cols: u16, rows: u16) -> bool {
        if !self.tty {
            return false;
        }
        self.touch();
        let input = self.input.lock().await;
        match input.as_ref() {
            Some(tx) => tx
                .send(InteractiveInput::Resize { cols, rows })
                .await
                .is_ok(),
            None => false,
        }
    }

    /// Kill the command: dropping its input ends the agent connection, and the
    /// agent kills the command when its connection closes.
    pub async fn kill(&self, reason: &str) {
        self.kill_with(Exit {
            code: None,
            error: Some(reason.to_string()),
        })
        .await
    }

    /// [`Self::kill`], recording `exit` as how it ended (unless it already had).
    pub async fn kill_with(&self, exit: Exit) {
        let running = {
            let mut inner = self.inner.lock();
            inner.killed = true;
            inner.exit.is_none()
        };
        self.acked_cv.notify_all();
        // Record the exit before the input goes: the session task then sees
        // the agent connection end and keeps this, the first, exit.
        if running {
            self.finish(exit);
        }
        self.input.lock().await.take();
    }

    /// Wait until the command runs or ended.
    pub async fn wait_started(&self) {
        let mut rx = self.changed.subscribe();
        loop {
            if self.state() != SessionState::Starting {
                return;
            }
            if rx.changed().await.is_err() {
                return;
            }
        }
    }

    /// Summary for a listing.
    pub fn summary(&self) -> SessionSummary {
        let inner = self.inner.lock();
        SessionSummary {
            exec_id: self.id.clone(),
            state: inner.state,
            exit_code: inner.exit.as_ref().and_then(|e| e.code),
            error: inner.exit.as_ref().and_then(|e| e.error.clone()),
            command: self.command.clone(),
            tty: self.tty,
            interactive: self.interactive,
            created_at: unix_millis(self.created_at),
            end: inner.end,
            attached: inner.attached,
        }
    }
}

/// One session in a listing.
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SessionSummary {
    /// The exec id.
    pub exec_id: String,
    #[schema(value_type = String)]
    /// Where the session is.
    pub state: SessionState,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The exit code, once it exited.
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Why it ended without one.
    pub error: Option<String>,
    /// The command and its arguments.
    pub command: Vec<String>,
    /// It runs on a PTY.
    pub tty: bool,
    /// Its stdin takes sequenced frames.
    pub interactive: bool,
    /// Unix milliseconds.
    pub created_at: u64,
    /// Bytes of output produced so far.
    pub end: u64,
    /// Readers attached over a WebSocket.
    pub attached: usize,
}

fn unix_millis(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Detaches a WebSocket reader when dropped.
pub struct AttachGuard(Arc<ExecSession>);

impl Drop for AttachGuard {
    fn drop(&mut self) {
        let mut inner = self.0.inner.lock();
        inner.attached = inner.attached.saturating_sub(1);
        inner.last_access = Instant::now();
    }
}

/// Why a session could not be registered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterError {
    /// The id names a session that ran a different command.
    Mismatch,
    /// The id ran and was collected or deleted.
    Spent,
    /// The node or machine holds as many sessions as it may.
    Full,
}

/// Every session on this node, by machine and id.
#[derive(Clone)]
pub struct ExecSessions {
    inner: Arc<Registry>,
}

struct Registry {
    limits: Limits,
    sessions: Mutex<HashMap<(String, String), Arc<ExecSession>>>,
    tombstones: Mutex<HashMap<(String, String), Instant>>,
    reaper_started: AtomicBool,
}

impl Default for ExecSessions {
    fn default() -> Self {
        Self::with_limits(Limits::from_env())
    }
}

impl ExecSessions {
    /// A registry with these limits (tests use short ones).
    pub fn with_limits(limits: Limits) -> Self {
        Self {
            inner: Arc::new(Registry {
                limits,
                sessions: Mutex::new(HashMap::new()),
                tombstones: Mutex::new(HashMap::new()),
                reaper_started: AtomicBool::new(false),
            }),
        }
    }

    /// The limits sessions are held to.
    pub fn limits(&self) -> Limits {
        self.inner.limits
    }

    /// The session `id` on `machine`.
    pub fn get(&self, machine: &str, id: &str) -> Option<Arc<ExecSession>> {
        self.inner
            .sessions
            .lock()
            .get(&(machine.to_string(), id.to_string()))
            .cloned()
    }

    /// Register a new session, or find the one a retried start already made.
    /// `Ok((session, true))` is new: the caller starts its command.
    #[allow(clippy::too_many_arguments)]
    pub fn register(
        &self,
        machine: &str,
        id: &str,
        command: Vec<String>,
        tty: bool,
        interactive: bool,
        fingerprint: Fingerprint,
    ) -> Result<(Arc<ExecSession>, bool), RegisterError> {
        self.start_reaper();
        let key = (machine.to_string(), id.to_string());
        let mut sessions = self.inner.sessions.lock();
        if let Some(existing) = sessions.get(&key) {
            return if existing.fingerprint == fingerprint {
                Ok((existing.clone(), false))
            } else {
                Err(RegisterError::Mismatch)
            };
        }
        if self.inner.tombstones.lock().contains_key(&key) {
            return Err(RegisterError::Spent);
        }
        let on_machine = sessions.keys().filter(|(m, _)| m == machine).count();
        if sessions.len() >= MAX_SESSIONS || on_machine >= MAX_SESSIONS_PER_MACHINE {
            // Make room by forgetting the oldest session whose exit was read.
            let victim = sessions
                .iter()
                .filter(|((m, _), s)| {
                    (sessions.len() >= MAX_SESSIONS || m == machine)
                        && s.inner.lock().collected_at.is_some()
                })
                .min_by_key(|(_, s)| s.created_at)
                .map(|(k, _)| k.clone());
            match victim {
                Some(k) => {
                    sessions.remove(&k);
                    self.inner.tombstones.lock().insert(k, Instant::now());
                }
                None => return Err(RegisterError::Full),
            }
        }
        let session = Arc::new(ExecSession::new(
            id.to_string(),
            machine.to_string(),
            command,
            tty,
            interactive,
            fingerprint,
            self.inner.limits,
        ));
        sessions.insert(key, session.clone());
        Ok((session, true))
    }

    /// Forget a session that never started (its start failed before the
    /// command ran), so a retry may start it.
    pub fn unregister(&self, machine: &str, id: &str) {
        self.inner
            .sessions
            .lock()
            .remove(&(machine.to_string(), id.to_string()));
    }

    /// Kill (if running) and forget a session. Its id stays spent.
    pub async fn remove(&self, machine: &str, id: &str) -> bool {
        let key = (machine.to_string(), id.to_string());
        let session = self.inner.sessions.lock().remove(&key);
        match session {
            Some(s) => {
                self.inner.tombstones.lock().insert(key, Instant::now());
                s.kill("deleted").await;
                true
            }
            None => false,
        }
    }

    /// Every session on `machine`.
    pub fn list(&self, machine: &str) -> Vec<Arc<ExecSession>> {
        let mut out: Vec<_> = self
            .inner
            .sessions
            .lock()
            .iter()
            .filter(|((m, _), _)| m == machine)
            .map(|(_, s)| s.clone())
            .collect();
        out.sort_by_key(|s| s.created_at);
        out
    }

    /// Kill and forget every session on a machine being deleted.
    pub async fn forget_machine(&self, machine: &str) {
        let removed: Vec<_> = {
            let mut sessions = self.inner.sessions.lock();
            let keys: Vec<_> = sessions
                .keys()
                .filter(|(m, _)| m == machine)
                .cloned()
                .collect();
            keys.into_iter()
                .filter_map(|k| sessions.remove(&k))
                .collect()
        };
        for s in removed {
            s.kill("machine deleted").await;
        }
    }

    /// How long each session whose command runs (or is starting) has been
    /// running, in milliseconds.
    pub fn running_ages_ms(&self) -> Vec<u64> {
        self.inner
            .sessions
            .lock()
            .values()
            .filter(|s| s.state() != SessionState::Exited)
            .map(|s| {
                s.created_at
                    .elapsed()
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0)
            })
            .collect()
    }

    /// Counts by state, for metrics: (running, exited).
    pub fn counts(&self) -> (usize, usize) {
        let sessions = self.inner.sessions.lock();
        let running = sessions
            .values()
            .filter(|s| s.state() != SessionState::Exited)
            .count();
        (running, sessions.len() - running)
    }

    /// Expire what is due once; returns the sessions removed. Run every few
    /// seconds by the reaper.
    pub async fn reap(&self) -> usize {
        let limits = self.inner.limits;
        let mut to_kill = Vec::new();
        let mut expired = Vec::new();
        {
            let sessions = self.inner.sessions.lock();
            for (key, s) in sessions.iter() {
                let inner = s.inner.lock();
                if inner.exit.is_none() {
                    if s.interactive && s.detached(&inner) {
                        to_kill.push(s.clone());
                    }
                    continue;
                }
                let since = inner
                    .exited_at
                    .map(|t| t.max(inner.last_access))
                    .unwrap_or(inner.last_access);
                let ttl = if inner.collected_at.is_some() {
                    COLLECTED_TTL
                } else {
                    limits.exit_ttl
                };
                if inner.attached == 0 && since.elapsed() >= ttl {
                    expired.push(key.clone());
                }
            }
        }
        for s in to_kill {
            tracing::info!(machine = %s.machine, exec = %s.id, "exec session: interactive session left without a reader; killing it");
            s.kill(&format!(
                "no client attached for {} s",
                limits.detach_grace.as_secs()
            ))
            .await;
        }
        let n = expired.len();
        if n > 0 {
            let mut sessions = self.inner.sessions.lock();
            let mut tombstones = self.inner.tombstones.lock();
            for key in expired {
                sessions.remove(&key);
                tombstones.insert(key, Instant::now());
            }
        }
        self.inner
            .tombstones
            .lock()
            .retain(|_, t| t.elapsed() < TOMBSTONE_TTL);
        let (running, exited) = self.counts();
        metrics::gauge!("smolvm_exec_sessions", "state" => "running").set(running as f64);
        metrics::gauge!("smolvm_exec_sessions", "state" => "exited").set(exited as f64);
        n
    }

    fn start_reaper(&self) {
        if self.inner.reaper_started.swap(true, Ordering::SeqCst) {
            return;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            self.inner.reaper_started.store(false, Ordering::SeqCst);
            return;
        };
        let weak = Arc::downgrade(&self.inner);
        handle.spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(2));
            loop {
                tick.tick().await;
                let Some(inner) = weak.upgrade() else { return };
                ExecSessions { inner }.reap().await;
            }
        });
    }
}

/// Map agent output onto a session.
pub fn output_of(o: InteractiveOutput) -> (OutputStream, Vec<u8>) {
    match o {
        InteractiveOutput::Stdout(d) => (OutputStream::Stdout, d),
        InteractiveOutput::Stderr(d) => (OutputStream::Stderr, d),
    }
}

/// Whether `id` may name an exec: 8 to 64 of `[A-Za-z0-9_-]`.
pub fn valid_exec_id(id: &str) -> bool {
    (8..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// A fresh random exec id.
pub fn new_exec_id() -> String {
    let mut bytes = [0u8; 16];
    if getrandom::fill(&mut bytes).is_err() {
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        bytes.copy_from_slice(&nanos.to_le_bytes());
    }
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(limits: Limits, interactive: bool) -> Arc<ExecSession> {
        Arc::new(ExecSession::new(
            "exec-0001".into(),
            "m".into(),
            vec!["true".into()],
            false,
            interactive,
            1,
            limits,
        ))
    }

    fn bytes_of(b: &Batch) -> Vec<u8> {
        b.output.iter().flat_map(|p| p.data.to_vec()).collect()
    }

    #[test]
    fn a_reader_that_advances_to_next_sees_each_byte_once() {
        let s = session(Limits::default(), false);
        s.push_output(OutputStream::Stdout, b"hello ".to_vec());
        s.push_output(OutputStream::Stderr, b"warn ".to_vec());
        s.push_output(OutputStream::Stdout, b"world".to_vec());
        let first = s.read(0, 8, true).unwrap();
        assert_eq!(bytes_of(&first), b"hello wa");
        assert_eq!(first.output[1].stream, OutputStream::Stderr);
        assert_eq!(first.output[1].offset, 6);
        // The answer was lost: asking again with the same offset repeats it.
        let again = s.read(0, 8, true).unwrap();
        assert_eq!(bytes_of(&again), b"hello wa");
        let rest = s.read(first.next, 1024, true).unwrap();
        assert_eq!(bytes_of(&rest), b"rn world");
        assert_eq!(rest.next, 16);
        assert!(!rest.done);
        s.finish(Exit {
            code: Some(3),
            error: None,
        });
        let last = s.read(rest.next, 1024, true).unwrap();
        assert!(last.done);
        assert_eq!(last.exit.unwrap().code, Some(3));
    }

    #[test]
    fn acknowledged_output_is_dropped_and_reading_before_it_reports_the_loss() {
        let s = session(Limits::default(), false);
        s.push_output(OutputStream::Stdout, b"0123456789".to_vec());
        let b = s.read(6, 100, true).unwrap();
        assert_eq!(bytes_of(&b), b"6789");
        assert_eq!(b.start, 0, "a chunk straddling the ack stays whole");
        s.push_output(OutputStream::Stdout, b"abc".to_vec());
        s.ack(10);
        let b = s.read(2, 100, false).unwrap();
        assert_eq!(b.lost, Some((2, 10)));
        assert_eq!(bytes_of(&b), b"abc");
    }

    #[tokio::test]
    async fn a_reader_that_comes_straight_back_for_a_little_output_is_paced() {
        let s = session(Limits::default(), false);
        s.push_output(OutputStream::Stdout, b"a".to_vec());
        let first = s.read(0, 10, true).unwrap();
        s.push_output(OutputStream::Stdout, b"b".to_vec());
        let t = std::time::Instant::now();
        s.pace(first.next).await;
        assert!(
            t.elapsed() >= Duration::from_millis(80),
            "{:?}",
            t.elapsed()
        );
        // A lot waiting, or the end, answers at once.
        s.read(first.next, 10, true).unwrap();
        s.push_output(OutputStream::Stdout, vec![b'x'; PACE_BATCH as usize]);
        let t = std::time::Instant::now();
        s.pace(2).await;
        assert!(t.elapsed() < Duration::from_millis(50));
    }

    #[test]
    fn a_read_beyond_the_end_is_refused() {
        let s = session(Limits::default(), false);
        s.push_output(OutputStream::Stdout, b"abc".to_vec());
        assert_eq!(s.read(4, 10, true).unwrap_err(), 3);
    }

    #[test]
    fn a_followed_command_waits_for_its_reader_and_loses_nothing() {
        let limits = Limits {
            window: 64 * 1024,
            detach_grace: Duration::from_secs(60),
            exit_ttl: Duration::from_secs(60),
        };
        let s = session(limits, false);
        let producer = {
            let s = s.clone();
            std::thread::spawn(move || {
                for i in 0..64u32 {
                    s.push_output(OutputStream::Stdout, vec![(i % 251) as u8; 16 * 1024]);
                }
                s.finish(Exit {
                    code: Some(0),
                    error: None,
                });
            })
        };
        let mut got = Vec::new();
        let mut next = 0;
        loop {
            let b = s.read(next, 20_000, true).unwrap();
            assert!(b.lost.is_none());
            assert!(b.end - next <= limits.window as u64 + 16 * 1024);
            got.extend(bytes_of(&b));
            next = b.next;
            if b.done {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        producer.join().unwrap();
        assert_eq!(got.len(), 64 * 16 * 1024);
        for (i, block) in got.chunks(16 * 1024).enumerate() {
            assert!(block.iter().all(|&b| b == (i as u32 % 251) as u8));
        }
    }

    #[test]
    fn a_detached_command_keeps_running_and_keeps_only_the_newest_window() {
        let limits = Limits {
            window: 64 * 1024,
            detach_grace: Duration::from_millis(0),
            exit_ttl: Duration::from_secs(60),
        };
        let s = session(limits, false);
        for _ in 0..10 {
            s.push_output(OutputStream::Stdout, vec![b'x'; 32 * 1024]);
        }
        let b = s.read(0, 1 << 20, true).unwrap();
        assert_eq!(b.lost, Some((0, 10 * 32 * 1024 - 64 * 1024)));
        assert_eq!(bytes_of(&b).len(), 64 * 1024);
    }

    #[tokio::test]
    async fn stdin_frames_apply_once_and_in_order() {
        let s = session(Limits::default(), true);
        let (tx, mut rx) = crate::agent::interactive_input(16).unwrap();
        s.set_input(tx).await;
        assert_eq!(s.apply_stdin(1, b"a", false).await, Ok(1));
        assert_eq!(
            s.apply_stdin(1, b"a", false).await,
            Ok(1),
            "a resend is ignored"
        );
        assert_eq!(
            s.apply_stdin(3, b"c", false).await,
            Err(StdinError::Gap { applied: 1 })
        );
        assert_eq!(s.apply_stdin(2, b"b", true).await, Ok(2));
        assert_eq!(
            s.apply_stdin(3, b"c", false).await,
            Err(StdinError::Closed { applied: 2 })
        );
        let mut got = Vec::new();
        while let Ok(event) = rx.try_recv() {
            got.push(event);
        }
        assert_eq!(
            got,
            vec![
                InteractiveInput::Stdin(b"a".to_vec()),
                InteractiveInput::Stdin(b"b".to_vec()),
                InteractiveInput::Eof
            ]
        );
    }

    #[tokio::test]
    async fn a_retried_start_finds_its_session_and_a_spent_id_is_refused() {
        let reg = ExecSessions::with_limits(Limits::default());
        let (a, new) = reg
            .register("m", "exec-aaaa", vec![], false, false, 7)
            .unwrap();
        assert!(new);
        let (b, new) = reg
            .register("m", "exec-aaaa", vec![], false, false, 7)
            .unwrap();
        assert!(!new && Arc::ptr_eq(&a, &b));
        assert_eq!(
            reg.register("m", "exec-aaaa", vec![], false, false, 8)
                .err(),
            Some(RegisterError::Mismatch)
        );
        // The same id on another machine is another session.
        assert!(
            reg.register("n", "exec-aaaa", vec![], false, false, 9)
                .unwrap()
                .1
        );
        assert!(reg.remove("m", "exec-aaaa").await);
        assert_eq!(
            reg.register("m", "exec-aaaa", vec![], false, false, 7)
                .err(),
            Some(RegisterError::Spent)
        );
    }

    #[tokio::test]
    async fn an_unread_interactive_session_is_killed_and_a_collected_exit_expires() {
        let limits = Limits {
            window: 64 * 1024,
            detach_grace: Duration::from_millis(0),
            exit_ttl: Duration::from_secs(600),
        };
        let reg = ExecSessions::with_limits(limits);
        let (shell, _) = reg
            .register("m", "exec-shell", vec![], true, true, 1)
            .unwrap();
        let (job, _) = reg
            .register("m", "exec-job1", vec![], false, false, 2)
            .unwrap();
        reg.reap().await;
        assert_eq!(shell.state(), SessionState::Exited);
        assert_eq!(
            job.state(),
            SessionState::Starting,
            "a detached plain exec keeps running"
        );
        assert!(
            reg.get("m", "exec-shell").is_some(),
            "its exit is still to be read"
        );
        assert!(valid_exec_id(&new_exec_id()));
    }
}
