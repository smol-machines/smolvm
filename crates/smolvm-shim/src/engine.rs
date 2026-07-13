//! Engine-backed [`PodBackend`]: one smolvm microVM per pod sandbox.
//!
//! Uses the embeddable engine API (`smolvm::embedded`, the same surface the
//! Python/Node SDKs drive) to boot/tear down the sandbox VM, and the agent's
//! Pod* protocol (see `smolvm_protocol::AgentRequest`) over vsock to run
//! containers inside it:
//!
//! - `create_sandbox` → create + start a persistent machine named after the
//!   sandbox id, with ONE host mount: `<bundle>/podshare` shared into the
//!   guest. Container rootfs dirs are bind-mounted under that share afterwards
//!   (virtiofs shares are fixed at boot; pod containers are created later).
//! - `create_container`/`create_exec` → bind-mount the rootfs into the share,
//!   then `PodCreate`/`PodExec` on a short-lived agent connection.
//! - `start` → a DEDICATED agent connection per process: `PodStart` streams
//!   `Started` → `Stdout`/`Stderr`… → `Exited` on that connection, pumped to
//!   containerd's fifos by a per-process blocking thread (see [`run_pump`]).
//! - `kill`/`pids`/`delete` → `PodSignal`/`PodPids`/`PodDelete`; deleting the
//!   sandbox id stops + deletes the machine itself.
//!
//! The engine API is synchronous, so every engine/agent call is wrapped in
//! `tokio::task::spawn_blocking`.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use log::{debug, warn};
use tokio::sync::watch;

use smolvm::agent::{AgentClient, HostMount, VmResources};
use smolvm::embedded::MachineSpec;
use smolvm::network::NetworkBackend;
use smolvm_protocol::{AgentRequest, AgentResponse};

use crate::backend::{ExitInfo, ExitWatch, PodBackend, ProcessSpec, Stdio};

/// Nominal guest target recorded on the sandbox's single [`HostMount`]
/// (host side: `<bundle>/podshare`). `HostMount` targets only take effect for
/// container `Run` mount tuples, which the pod datapath doesn't use — the
/// actual guest mount is performed by [`mount_pod_share_in_guest`] at
/// [`POD_SHARE_GUEST_MOUNT`].
/// Host root for pod shares — a dedicated, non-protected location (the OCI
/// bundle lives under /run/containerd, which the engine's mount validation
/// rejects). One `<id>/podshare` subdir per sandbox.
const POD_SHARE_HOST_ROOT: &str = "/var/lib/containerd-shim-smolvm";

const POD_SHARE_GUEST_PATH: &str = "/podshare";

/// Where the agent's pod handlers resolve `PodCreate.rootfs_rel` from:
/// `paths::VIRTIOFS_MOUNT_ROOT` + `pod::POD_SHARE_TAG` in smolvm-agent. Must
/// stay in lockstep with those constants.
const POD_SHARE_GUEST_MOUNT: &str = "/mnt/virtiofs/podshare";

/// Default sandbox VM sizing until pod-overhead plumbing lands.
const SANDBOX_CPUS: u8 = 2;
const SANDBOX_MEMORY_MIB: u32 = 1024;

/// How long `start` waits for the agent's `Started` frame.
const START_TIMEOUT: Duration = Duration::from_secs(60);

/// Pump poll cadence: the streaming connection's read timeout, which bounds
/// how stale stdin/resize forwarding can get.
const PUMP_POLL: Duration = Duration::from_millis(50);

/// Synthetic guest-process pids reported to containerd. The agent does not
/// report real guest pids on `Started`, and containerd only needs a stable,
/// non-zero identifier per process.
static NEXT_PID: AtomicU32 = AtomicU32::new(1000);

fn next_pid() -> u32 {
    NEXT_PID.fetch_add(1, Ordering::Relaxed)
}

fn now_ns() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

fn key(id: &str, exec_id: Option<&str>) -> String {
    match exec_id {
        Some(e) if !e.is_empty() => format!("{id}/{e}"),
        _ => id.to_string(),
    }
}

/// Commands the async side sends into a process's pump thread. The pump owns
/// the process's streaming agent connection, so PTY resizes and stdin-close
/// must be relayed through it.
enum PumpCmd {
    Resize { cols: u16, rows: u16 },
    CloseStdin,
}

struct Sandbox {
    /// Sandbox task id == machine name.
    id: String,
    /// Host dir shared into the guest (`<bundle>/podshare`).
    share_dir: PathBuf,
    /// Host-side unix socket bridging to the guest agent's vsock port.
    socket: PathBuf,
    /// Pod network namespace path (recorded now, wired by the netns-tap
    /// backend later — see docs/kubernetes-runtime.md "Networking detail").
    #[allow(dead_code)]
    netns: Option<String>,
    /// Pod UTS hostname from the sandbox OCI spec. Injected into each container's
    /// spec (containerd puts the pod hostname on the sandbox, not the container).
    hostname: Option<String>,
    /// Pod sysctls (`linux.sysctl` on the sandbox OCI spec). Merged into every
    /// container's spec so crun applies them in the container's namespaces —
    /// the VM-per-pod equivalent of runc inheriting them from the shared pause.
    sysctls: Option<serde_json::Value>,
}

struct ProcEntry {
    stdio: Stdio,
    pid: u32,
    exit_tx: Arc<watch::Sender<Option<ExitInfo>>>,
    exit_rx: ExitWatch,
    /// Present once the process was started (the pump thread is running).
    cmd_tx: Option<std::sync::mpsc::Sender<PumpCmd>>,
}

impl ProcEntry {
    fn new(stdio: Stdio, pid: u32) -> Self {
        let (tx, rx) = watch::channel(None);
        Self {
            stdio,
            pid,
            exit_tx: Arc::new(tx),
            exit_rx: rx,
            cmd_tx: None,
        }
    }
}

pub struct EnginePodBackend {
    sandbox: Mutex<Option<Arc<Sandbox>>>,
    procs: Mutex<HashMap<String, ProcEntry>>,
}

impl EnginePodBackend {
    pub fn new() -> Self {
        // Once per shim process, reclaim sandbox VMs left behind by a node reboot
        // or a shim crash (dead process, but the persistent record + disk images
        // survive). containerd can't drive this cleanup after a reboot — its task
        // state in /run is gone, so it never asks us to delete those sandboxes.
        static RECONCILED: std::sync::Once = std::sync::Once::new();
        RECONCILED.call_once(|| match smolvm::embedded::runtime() {
            Ok(rt) => match rt.reconcile_runtime_machines() {
                Ok(n) if n > 0 => log::info!("reclaimed {n} stale sandbox VM(s) at startup"),
                Ok(_) => {}
                Err(e) => log::warn!("startup sandbox reconcile failed: {e}"),
            },
            Err(e) => log::warn!("startup sandbox reconcile: runtime unavailable: {e}"),
        });
        Self {
            sandbox: Mutex::new(None),
            procs: Mutex::new(HashMap::new()),
        }
    }

    fn sandbox(&self) -> Result<Arc<Sandbox>, String> {
        self.sandbox
            .lock()
            .map_err(|e| e.to_string())?
            .clone()
            .ok_or_else(|| "no sandbox created for this pod".to_string())
    }

    fn is_sandbox_task(&self, id: &str, exec_id: Option<&str>) -> bool {
        exec_id.is_none()
            && self
                .sandbox
                .lock()
                .ok()
                .and_then(|s| s.as_ref().map(|s| s.id == id))
                .unwrap_or(false)
    }

    fn insert_proc(&self, k: String, entry: ProcEntry) -> Result<(), String> {
        self.procs
            .lock()
            .map_err(|e| e.to_string())?
            .insert(k, entry);
        Ok(())
    }
}

// ========================== blocking agent helpers ==========================

fn connect(socket: &Path) -> Result<AgentClient, String> {
    AgentClient::connect_with_retry(socket).map_err(|e| format!("connect to sandbox agent: {e}"))
}

/// One-shot request/response on a fresh agent connection. All Pod* control
/// requests (create/exec/signal/pids/delete) are single-frame exchanges, so a
/// short-lived connection per request keeps them independent of the per-process
/// streaming connections.
fn pod_request(socket: &Path, req: &AgentRequest) -> Result<AgentResponse, String> {
    let mut client = connect(socket)?;
    client
        .send_raw(req)
        .map_err(|e| format!("send {}: {e}", req.log_summary()))?;
    // Skip Progress-style frames; return the first terminal response.
    loop {
        match client
            .recv_raw()
            .map_err(|e| format!("recv {}: {e}", req.log_summary()))?
        {
            AgentResponse::Progress { .. } => continue,
            resp => return Ok(resp),
        }
    }
}

fn expect_ok(resp: AgentResponse, op: &str) -> Result<(), String> {
    match resp {
        AgentResponse::Ok { .. } => Ok(()),
        AgentResponse::Error { message, .. } => Err(format!("{op}: {message}")),
        other => Err(format!("{op}: unexpected agent response {other:?}")),
    }
}

/// Mount the sandbox's shared virtiofs directory where the agent's pod
/// handlers expect it: `/mnt/virtiofs/podshare` (the agent's
/// `paths::VIRTIOFS_MOUNT_ROOT` + `pod::POD_SHARE_TAG`).
///
/// Two conventions are bridged here. The launcher tags virtiofs devices
/// `smolvm{index}` (`HostMount::mount_tag`) — the sandbox's single share is
/// therefore device tag `smolvm0` — and the agent only mounts tags lazily when
/// a `Run` request references them, which the pod datapath never does. So the
/// shim mounts the device itself, once, right after boot, via `VmExec` in the
/// agent rootfs. Idempotent (`mountpoint -q ||`) for shim-reconnect paths.
/// Apply the pod's `net.*` sysctls to the guest kernel. Pod containers declare
/// no network namespace of their own, so they share the guest's — writing these
/// under the guest's `/proc/sys/net` is what every container in the pod observes.
/// Best-effort: a sysctl the guest kernel doesn't expose is skipped, never fatal
/// to sandbox creation (matching the rest of the sandbox setup path).
fn apply_guest_net_sysctls(
    socket: &Path,
    sysctls: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), String> {
    let mut cmds = Vec::new();
    for (k, v) in sysctls {
        if !k.starts_with("net.") {
            continue;
        }
        let Some(val) = v.as_str() else { continue };
        // Reject values containing a single quote so the shell-quoting below is
        // safe; sysctl values are numbers or space/tab-separated number ranges.
        if val.contains('\'') {
            continue;
        }
        let path = format!("/proc/sys/{}", k.replace('.', "/"));
        cmds.push(format!("printf '%s' '{val}' > {path} 2>/dev/null || true"));
    }
    if cmds.is_empty() {
        return Ok(());
    }
    let resp = pod_request(
        socket,
        &AgentRequest::VmExec {
            command: vec!["/bin/sh".into(), "-c".into(), cmds.join("; ")],
            env: Vec::new(),
            workdir: None,
            timeout_ms: Some(10_000),
            interactive: false,
            tty: false,
            background: false,
            stdin_data: None,
        },
    )?;
    match resp {
        AgentResponse::Completed { .. } => Ok(()),
        other => Err(format!(
            "apply net sysctls: unexpected agent response {other:?}"
        )),
    }
}

fn mount_pod_share_in_guest(socket: &Path) -> Result<(), String> {
    let share_tag = HostMount::mount_tag(0);
    let script = format!(
        "mkdir -p {POD_SHARE_GUEST_MOUNT} && \
         (mountpoint -q {POD_SHARE_GUEST_MOUNT} || \
          mount -t virtiofs {share_tag} {POD_SHARE_GUEST_MOUNT})"
    );
    let resp = pod_request(
        socket,
        &AgentRequest::VmExec {
            command: vec!["/bin/sh".into(), "-c".into(), script],
            env: Vec::new(),
            workdir: None,
            timeout_ms: Some(10_000),
            interactive: false,
            tty: false,
            background: false,
            stdin_data: None,
        },
    )?;
    match resp {
        AgentResponse::Completed { exit_code: 0, .. } => Ok(()),
        AgentResponse::Completed {
            exit_code, stderr, ..
        } => Err(format!(
            "mount pod share in guest failed (exit {exit_code}): {}",
            String::from_utf8_lossy(&stderr)
        )),
        AgentResponse::Error { message, .. } => Err(format!("mount pod share in guest: {message}")),
        other => Err(format!(
            "mount pod share in guest: unexpected agent response {other:?}"
        )),
    }
}

/// True when a client error is the pump's poll-cadence read timeout rather
/// than a real failure (`PUMP_POLL` read timeout on the streaming socket).
fn is_timeout(e: &smolvm::Error) -> bool {
    e.is_io()
        && matches!(
            e.source_io_error_kind(),
            Some(std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)
        )
}

// ================================ stdio pump ================================

fn open_fifo_writer(path: &str) -> Option<std::fs::File> {
    if path.is_empty() {
        return None;
    }
    // Blocks until the read end is open; containerd wires its fifo readers up
    // before Start/Exec return, so this resolves promptly.
    match std::fs::OpenOptions::new().write(true).open(path) {
        Ok(f) => Some(f),
        Err(e) => {
            warn!("open fifo {path} for write: {e}");
            None
        }
    }
}

fn open_fifo_stdin(path: &str) -> Option<std::fs::File> {
    if path.is_empty() {
        return None;
    }
    // O_RDWR (not O_RDONLY) so the fifo always has a writer and reads never
    // return a spurious EOF before containerd attaches; real stdin close is
    // signalled explicitly via the CloseIO RPC → PumpCmd::CloseStdin.
    // O_NONBLOCK so the single pump thread can poll it between output frames.
    use std::os::unix::fs::OpenOptionsExt;
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(nix::libc::O_NONBLOCK)
        .open(path)
    {
        Ok(f) => Some(f),
        Err(e) => {
            warn!("open stdin fifo {path}: {e}");
            None
        }
    }
}

/// Per-process stdio pump. Runs on its own blocking thread and OWNS the
/// process's dedicated streaming agent connection:
///
/// ```text
///   async trait methods ──(mpsc PumpCmd: Resize/CloseStdin)──► pump thread
///   stdin fifo (nonblocking read) ──────────────────────────►    │
///   agent Stdout/Stderr frames ◄── vsock ── PodStart connection ─┘
///        │                                     │
///        ▼                                     ▼
///   stdout/stderr fifos                Exited → watch<ExitInfo>
/// ```
///
/// Sequence: connect → `PodStart` → wait `Started` → ack `started_tx` (this is
/// what unblocks the Task API `Start` call) → open fifos → poll loop. The loop
/// alternates: drain `PumpCmd`s, forward pending stdin bytes as `Stdin`
/// requests, then block up to [`PUMP_POLL`] for one agent frame. On `Exited`
/// the exit is published on the watch channel exactly once and the thread
/// (and its connection) winds down; any earlier failure publishes exit 255 so
/// waiters never hang.
#[allow(clippy::too_many_arguments)]
fn run_pump(
    socket: PathBuf,
    id: String,
    exec_id: Option<String>,
    stdio: Stdio,
    exit_tx: Arc<watch::Sender<Option<ExitInfo>>>,
    cmd_rx: Receiver<PumpCmd>,
    started_tx: SyncSender<Result<(), String>>,
) {
    // Phase 1: dedicated connection + PodStart + Started.
    let setup = || -> Result<AgentClient, String> {
        let mut client = connect(&socket)?;
        client
            .send_raw(&AgentRequest::PodStart {
                id: id.clone(),
                exec_id: exec_id.clone(),
            })
            .map_err(|e| format!("send PodStart: {e}"))?;
        match client
            .recv_raw()
            .map_err(|e| format!("recv PodStart: {e}"))?
        {
            AgentResponse::Started => Ok(client),
            AgentResponse::Error { message, .. } => Err(format!("PodStart: {message}")),
            other => Err(format!("PodStart: unexpected response {other:?}")),
        }
    };
    let mut client = match setup() {
        Ok(c) => c,
        Err(e) => {
            let _ = started_tx.send(Err(e));
            return;
        }
    };
    let _ = started_tx.send(Ok(()));

    // Phase 2: pump until Exited (or the connection dies).
    if let Err(e) = pump_loop(&mut client, &stdio, &exit_tx, &cmd_rx) {
        warn!("stdio pump for {}: {e}", key(&id, exec_id.as_deref()));
    }
    // Never leave waiters hanging: if the loop ended without a real exit
    // (connection lost, agent error), publish exit 255.
    if exit_tx.borrow().is_none() {
        let _ = exit_tx.send(Some(ExitInfo {
            status: 255,
            exited_at_ns: now_ns(),
            oom: false,
        }));
    }
}

fn pump_loop(
    client: &mut AgentClient,
    stdio: &Stdio,
    exit_tx: &watch::Sender<Option<ExitInfo>>,
    cmd_rx: &Receiver<PumpCmd>,
) -> Result<(), String> {
    let mut stdout = open_fifo_writer(&stdio.stdout);
    // A terminal process multiplexes all output on the PTY (stdout); the agent
    // only sends Stderr frames for non-tty processes.
    let mut stderr = if stdio.terminal {
        None
    } else {
        open_fifo_writer(&stdio.stderr)
    };
    let mut stdin = open_fifo_stdin(&stdio.stdin);

    // Poll-cadence read timeout for the frame loop; the guard restores the
    // default on drop (moot — the connection is dropped with the pump).
    let _guard = client
        .set_extended_read_timeout(PUMP_POLL)
        .map_err(|e| format!("set pump read timeout: {e}"))?;

    let mut inbuf = [0u8; 8192];
    loop {
        // 1) Relay commands from the async side.
        loop {
            match cmd_rx.try_recv() {
                Ok(PumpCmd::Resize { cols, rows }) => {
                    client
                        .send_raw(&AgentRequest::Resize { cols, rows })
                        .map_err(|e| format!("send Resize: {e}"))?;
                }
                Ok(PumpCmd::CloseStdin) => {
                    if stdin.take().is_some() {
                        // Empty Stdin frame = EOF (matches the interactive protocol).
                        client
                            .send_raw(&AgentRequest::Stdin { data: Vec::new() })
                            .map_err(|e| format!("send stdin EOF: {e}"))?;
                    }
                }
                // Empty: nothing pending. Disconnected: backend entry deleted;
                // keep pumping output until the process exits.
                Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => break,
            }
        }

        // 2) Forward pending stdin bytes.
        if let Some(f) = stdin.as_mut() {
            match f.read(&mut inbuf) {
                Ok(0) => {
                    // Can't happen while we hold the O_RDWR write end, but be
                    // safe: treat as EOF.
                    stdin = None;
                    client
                        .send_raw(&AgentRequest::Stdin { data: Vec::new() })
                        .map_err(|e| format!("send stdin EOF: {e}"))?;
                }
                Ok(n) => {
                    client
                        .send_raw(&AgentRequest::Stdin {
                            data: inbuf[..n].to_vec(),
                        })
                        .map_err(|e| format!("send Stdin: {e}"))?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    warn!("read stdin fifo: {e}");
                    stdin = None;
                }
            }
        }

        // 3) One agent frame (blocks up to PUMP_POLL).
        match client.recv_raw() {
            Ok(AgentResponse::Stdout { data }) => {
                if let Some(f) = stdout.as_mut() {
                    if let Err(e) = f.write_all(&data) {
                        // Reader side gone (EPIPE): stop writing, keep pumping.
                        debug!("write stdout fifo: {e}");
                        stdout = None;
                    }
                }
            }
            Ok(AgentResponse::Stderr { data }) => {
                if let Some(f) = stderr.as_mut() {
                    if let Err(e) = f.write_all(&data) {
                        debug!("write stderr fifo: {e}");
                        stderr = None;
                    }
                }
            }
            Ok(AgentResponse::Exited { exit_code, oom }) => {
                let _ = exit_tx.send(Some(ExitInfo {
                    status: exit_code as u32,
                    exited_at_ns: now_ns(),
                    oom,
                }));
                return Ok(());
            }
            Ok(AgentResponse::Error { message, .. }) => {
                return Err(format!("agent error: {message}"));
            }
            Ok(_) => {}
            Err(e) if is_timeout(&e) => {}
            Err(e) => return Err(format!("streaming connection lost: {e}")),
        }
    }
}

// ============================== trait impl ==================================

#[async_trait]
impl PodBackend for EnginePodBackend {
    async fn create_sandbox(
        &self,
        id: &str,
        bundle: &str,
        netns: Option<&str>,
    ) -> Result<u32, String> {
        let id_owned = id.to_string();
        let bundle = bundle.to_string();
        let netns = netns.map(str::to_string);

        let (sandbox, pid) = tokio::task::spawn_blocking(move || {
            // The pod hostname and sysctls are on the SANDBOX OCI spec (containerd
            // doesn't put them on each container's spec); read them now to inject
            // into every container.
            let sandbox_spec = std::fs::read_to_string(Path::new(&bundle).join("config.json"))
                .ok()
                .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok());
            let hostname = sandbox_spec.as_ref().and_then(|v| {
                v.get("hostname")
                    .and_then(|h| h.as_str())
                    .filter(|s| !s.is_empty())
                    .map(String::from)
            });
            let sysctls = sandbox_spec
                .as_ref()
                .and_then(|v| v.pointer("/linux/sysctl"))
                .filter(|v| v.as_object().map(|o| !o.is_empty()).unwrap_or(false))
                .cloned();

            // The bundle lives under /run/containerd/... which the engine's mount
            // validation rejects as a protected system path. Host the pod share
            // in a dedicated, non-protected dir keyed by sandbox id instead.
            let share_dir = Path::new(POD_SHARE_HOST_ROOT)
                .join(&id_owned)
                .join("podshare");
            std::fs::create_dir_all(&share_dir)
                .map_err(|e| format!("mkdir {}: {e}", share_dir.display()))?;

            let rt = smolvm::embedded::runtime().map_err(|e| e.to_string())?;
            let mount = HostMount::new(&share_dir, POD_SHARE_GUEST_PATH, false)
                .map_err(|e| format!("pod share mount: {e}"))?;
            let spec = MachineSpec {
                name: id_owned.clone(),
                mounts: vec![mount],
                ports: Vec::new(),
                resources: VmResources {
                    cpus: SANDBOX_CPUS,
                    memory_mib: SANDBOX_MEMORY_MIB,
                    network: true,
                    // virtio-net (not TSI) gives the sandbox a real L2 NIC — the
                    // prerequisite for bridging it to a CNI tap in the pod netns
                    // so the pod carries its CNI-assigned IP.
                    network_backend: Some(NetworkBackend::VirtioNet),
                    ..VmResources::default()
                },
                persistent: true,
                runtime_managed: true,
            };
            match rt.create_machine(spec.clone()) {
                Ok(()) => {}
                // A stale record with this sandbox id (crashed shim, unclean
                // node shutdown) can't be reused: replace it.
                Err(smolvm::Error::Agent {
                    kind: smolvm::error::AgentErrorKind::Conflict,
                    ..
                }) => {
                    warn!("sandbox machine {id_owned} already exists; recreating");
                    let _ = rt.delete_machine(&id_owned);
                    rt.create_machine(spec).map_err(|e| e.to_string())?;
                }
                Err(e) => return Err(e.to_string()),
            }
            // With a CNI netns, bridge the sandbox's virtio-net NIC into it so
            // the pod carries its CNI-assigned IP; otherwise a plain start (the
            // VM keeps smolvm's NAT gateway — outbound only, no pod IP).
            match netns.as_deref() {
                Some(ns) => rt
                    .start_machine_with_netns(&id_owned, std::path::PathBuf::from(ns))
                    .map_err(|e| format!("start sandbox VM (netns {ns}): {e}"))?,
                None => rt
                    .start_machine(&id_owned)
                    .map_err(|e| format!("start sandbox VM: {e}"))?,
            }

            let pid = rt
                .pid(&id_owned)
                .and_then(|p| u32::try_from(p).ok())
                .unwrap_or(1);
            let socket = smolvm::agent::vm_data_dir(&id_owned).join("agent.sock");
            mount_pod_share_in_guest(&socket)?;
            // Pod net.* sysctls apply guest-wide (shared net namespace); the
            // ipc/uts ones ride on each container's spec (see materialize_bind_mounts).
            if let Some(serde_json::Value::Object(map)) = sysctls.as_ref() {
                apply_guest_net_sysctls(&socket, map)?;
            }
            Ok::<_, String>((
                Sandbox {
                    id: id_owned,
                    share_dir,
                    socket,
                    netns,
                    hostname,
                    sysctls,
                },
                pid,
            ))
        })
        .await
        .map_err(|e| e.to_string())??;

        *self.sandbox.lock().map_err(|e| e.to_string())? = Some(Arc::new(sandbox));
        self.insert_proc(key(id, None), ProcEntry::new(Stdio::default(), pid))?;
        Ok(pid)
    }

    async fn create_container(&self, id: &str, spec: ProcessSpec) -> Result<u32, String> {
        let sandbox = self.sandbox()?;
        let id_owned = id.to_string();
        let stdio = spec.stdio.clone();
        let pid = next_pid();

        tokio::task::spawn_blocking(move || {
            // Materialize the container rootfs under the pod share as plain
            // files, so the guest sees it through the boot-time virtiofs mount.
            //
            // We deliberately COPY rather than bind-mount the containerd overlay:
            // an overlayfs re-exported through virtiofs can't service the guest's
            // copy-up writes (crun's `mkdir /proc` fails EACCES), the same reason
            // Kata doesn't stack overlay-on-virtiofs. A per-container copy is also
            // semantically correct for Kubernetes — the container filesystem is
            // ephemeral (writes vanish on container delete), which is exactly the
            // lifecycle of this copy. `cp -a` preserves modes/owners/symlinks;
            // reflink makes it near-free when the share and snapshot share a fs.
            let target = sandbox.share_dir.join(&id_owned).join("rootfs");
            std::fs::create_dir_all(&target)
                .map_err(|e| format!("mkdir {}: {e}", target.display()))?;
            let src_glob = format!("{}/.", spec.rootfs);
            let status = std::process::Command::new("cp")
                .args(["-a", "--reflink=auto", &src_glob])
                .arg(&target)
                .status()
                .map_err(|e| format!("spawn cp for rootfs: {e}"))?;
            if !status.success() {
                return Err(format!(
                    "copy rootfs {} -> {}: cp exited {status}",
                    spec.rootfs,
                    target.display()
                ));
            }

            let config = Path::new(&spec.bundle).join("config.json");
            let spec_json = std::fs::read_to_string(&config)
                .map_err(|e| format!("read {}: {e}", config.display()))?;

            // Copy the CRI bind mounts (volumes + generated /etc/resolv.conf,
            // /etc/hosts, /etc/hostname, etc.) into the pod share and rewrite
            // their sources to the guest-visible path, so the agent can
            // materialize them into the container's writable overlay. Also inject
            // the pod hostname (which lives on the sandbox spec, not the container).
            let spec_json = materialize_bind_mounts(
                &spec_json,
                &sandbox.share_dir,
                &id_owned,
                sandbox.hostname.as_deref(),
                sandbox.sysctls.as_ref(),
            )?;

            let resp = pod_request(
                &sandbox.socket,
                &AgentRequest::PodCreate {
                    id: id_owned.clone(),
                    rootfs_rel: format!("{id_owned}/rootfs"),
                    spec_json,
                    tty: spec.stdio.terminal,
                },
            )?;
            expect_ok(resp, "PodCreate")
        })
        .await
        .map_err(|e| e.to_string())??;

        self.insert_proc(key(id, None), ProcEntry::new(stdio, pid))?;
        Ok(pid)
    }

    async fn create_exec(&self, id: &str, exec_id: &str, spec: ProcessSpec) -> Result<(), String> {
        let sandbox = self.sandbox()?;
        let id_owned = id.to_string();
        let exec_owned = exec_id.to_string();
        let stdio = spec.stdio.clone();

        // containerd's ExecProcessRequest.spec is an Any whose value is the
        // OCI Process serialized as JSON — pass it through verbatim.
        let process_json = String::from_utf8(spec.exec_spec.unwrap_or_default())
            .map_err(|e| format!("exec spec is not UTF-8 JSON: {e}"))?;

        tokio::task::spawn_blocking(move || {
            let resp = pod_request(
                &sandbox.socket,
                &AgentRequest::PodExec {
                    id: id_owned,
                    exec_id: exec_owned,
                    process_json,
                    tty: spec.stdio.terminal,
                },
            )?;
            expect_ok(resp, "PodExec")
        })
        .await
        .map_err(|e| e.to_string())??;

        self.insert_proc(key(id, Some(exec_id)), ProcEntry::new(stdio, next_pid()))?;
        Ok(())
    }

    async fn start(&self, id: &str, exec_id: Option<&str>) -> Result<u32, String> {
        let k = key(id, exec_id);
        let (stdio, pid, exit_tx) = {
            let map = self.procs.lock().map_err(|e| e.to_string())?;
            let p = map.get(&k).ok_or_else(|| format!("no such process {k}"))?;
            (p.stdio.clone(), p.pid, p.exit_tx.clone())
        };

        // The sandbox task is nominal — the VM already runs; there is no guest
        // process to start.
        if self.is_sandbox_task(id, exec_id) {
            return Ok(pid);
        }

        let sandbox = self.sandbox()?;
        let (cmd_tx, cmd_rx) = std::sync::mpsc::channel();
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
        let socket = sandbox.socket.clone();
        let id_owned = id.to_string();
        let exec_owned = exec_id.map(str::to_string);

        // The pump owns the process's dedicated streaming connection for its
        // whole lifetime — a plain thread, not a tokio blocking task.
        std::thread::Builder::new()
            .name(format!("pod-io-{k}"))
            .spawn(move || {
                run_pump(
                    socket, id_owned, exec_owned, stdio, exit_tx, cmd_rx, started_tx,
                )
            })
            .map_err(|e| format!("spawn pump thread: {e}"))?;

        // Block (off the async runtime) until the agent confirms Started.
        tokio::task::spawn_blocking(move || match started_rx.recv_timeout(START_TIMEOUT) {
            Ok(res) => res,
            Err(e) => Err(format!("timed out waiting for Started: {e}")),
        })
        .await
        .map_err(|e| e.to_string())??;

        if let Some(p) = self.procs.lock().map_err(|e| e.to_string())?.get_mut(&k) {
            p.cmd_tx = Some(cmd_tx);
        }
        Ok(pid)
    }

    async fn kill(
        &self,
        id: &str,
        exec_id: Option<&str>,
        signal: u32,
        all: bool,
    ) -> Result<(), String> {
        // Killing the sandbox task ends the nominal pause process: publish its
        // exit so Wait resolves. The VM itself is torn down by delete().
        if self.is_sandbox_task(id, exec_id) {
            if signal == 9 || signal == 15 {
                let k = key(id, None);
                if let Some(p) = self.procs.lock().map_err(|e| e.to_string())?.get(&k) {
                    let _ = p.exit_tx.send(Some(ExitInfo {
                        status: 128 + signal,
                        exited_at_ns: now_ns(),
                        oom: false,
                    }));
                }
            }
            return Ok(());
        }

        let sandbox = self.sandbox()?;
        let req = AgentRequest::PodSignal {
            id: id.to_string(),
            exec_id: exec_id.map(str::to_string),
            signal,
            all,
        };
        tokio::task::spawn_blocking(move || {
            expect_ok(pod_request(&sandbox.socket, &req)?, "PodSignal")
        })
        .await
        .map_err(|e| e.to_string())?
    }

    async fn wait_channel(&self, id: &str, exec_id: Option<&str>) -> Result<ExitWatch, String> {
        let map = self.procs.lock().map_err(|e| e.to_string())?;
        map.get(&key(id, exec_id))
            .map(|p| p.exit_rx.clone())
            .ok_or_else(|| format!("no such process {}", key(id, exec_id)))
    }

    async fn resize_pty(
        &self,
        id: &str,
        exec_id: Option<&str>,
        w: u32,
        h: u32,
    ) -> Result<(), String> {
        let cmd_tx = {
            let map = self.procs.lock().map_err(|e| e.to_string())?;
            map.get(&key(id, exec_id)).and_then(|p| p.cmd_tx.clone())
        };
        // Not started (or already exited): resize is a no-op.
        if let Some(tx) = cmd_tx {
            let _ = tx.send(PumpCmd::Resize {
                cols: w as u16,
                rows: h as u16,
            });
        }
        Ok(())
    }

    async fn close_io(&self, id: &str, exec_id: Option<&str>) -> Result<(), String> {
        let cmd_tx = {
            let map = self.procs.lock().map_err(|e| e.to_string())?;
            map.get(&key(id, exec_id)).and_then(|p| p.cmd_tx.clone())
        };
        if let Some(tx) = cmd_tx {
            let _ = tx.send(PumpCmd::CloseStdin);
        }
        Ok(())
    }

    async fn delete(&self, id: &str, exec_id: Option<&str>) -> Result<(), String> {
        let k = key(id, exec_id);

        if self.is_sandbox_task(id, exec_id) {
            // Sandbox delete = tear down the whole VM.
            let sandbox = self.sandbox()?;
            tokio::task::spawn_blocking(move || {
                let rt = smolvm::embedded::runtime().map_err(|e| e.to_string())?;
                if let Err(e) = rt.stop_machine(&sandbox.id) {
                    warn!("stop sandbox VM {}: {e}", sandbox.id);
                }
                rt.delete_machine(&sandbox.id)
                    .map_err(|e| format!("delete sandbox VM: {e}"))
            })
            .await
            .map_err(|e| e.to_string())??;
            *self.sandbox.lock().map_err(|e| e.to_string())? = None;
            self.procs.lock().map_err(|e| e.to_string())?.remove(&k);
            return Ok(());
        }

        let sandbox = self.sandbox()?;
        let id_owned = id.to_string();
        let exec_owned = exec_id.map(str::to_string);
        tokio::task::spawn_blocking(move || {
            // Best-effort guest-side cleanup: the VM may already be gone when
            // containerd deletes exited tasks during pod teardown, and a
            // failing Delete would wedge containerd's teardown loop.
            match pod_request(
                &sandbox.socket,
                &AgentRequest::PodDelete {
                    id: id_owned.clone(),
                    exec_id: exec_owned.clone(),
                },
            )
            .and_then(|r| expect_ok(r, "PodDelete"))
            {
                Ok(()) => {}
                Err(e) => warn!("PodDelete {id_owned}: {e}"),
            }

            // Container (not exec) delete removes the materialized rootfs copy
            // under the pod share (the container filesystem is ephemeral).
            if exec_owned.is_none() {
                let cdir = sandbox.share_dir.join(&id_owned);
                if let Err(e) = std::fs::remove_dir_all(&cdir) {
                    debug!("rm {}: {e}", cdir.display());
                }
            }
            Ok::<(), String>(())
        })
        .await
        .map_err(|e| e.to_string())??;

        self.procs.lock().map_err(|e| e.to_string())?.remove(&k);
        Ok(())
    }

    async fn pids(&self, id: &str) -> Result<Vec<u32>, String> {
        if self.is_sandbox_task(id, None) {
            let map = self.procs.lock().map_err(|e| e.to_string())?;
            let pid = map.get(&key(id, None)).map(|p| p.pid).unwrap_or(1);
            return Ok(vec![pid]);
        }
        let sandbox = self.sandbox()?;
        let req = AgentRequest::PodPids { id: id.to_string() };
        tokio::task::spawn_blocking(move || match pod_request(&sandbox.socket, &req)? {
            AgentResponse::Pids { pids } => Ok(pids),
            AgentResponse::Error { message, .. } => Err(format!("PodPids: {message}")),
            other => Err(format!("PodPids: unexpected agent response {other:?}")),
        })
        .await
        .map_err(|e| e.to_string())?
    }

    async fn stats(&self, id: &str) -> Result<Option<Vec<u8>>, String> {
        // The pod sandbox "task" has no container process tree to sample.
        if self.is_sandbox_task(id, None) {
            return Ok(None);
        }
        let sandbox = self.sandbox()?;
        let req = AgentRequest::PodStats { id: id.to_string() };
        tokio::task::spawn_blocking(move || {
            let (cpu_ns, mem_bytes) = match pod_request(&sandbox.socket, &req)? {
                AgentResponse::Stats {
                    cpu_usage_ns,
                    memory_bytes,
                } => (cpu_usage_ns, memory_bytes),
                AgentResponse::Error { message, .. } => return Err(format!("PodStats: {message}")),
                other => return Err(format!("PodStats: unexpected agent response {other:?}")),
            };
            Ok(Some(encode_cgroup_metrics(cpu_ns, mem_bytes)?))
        })
        .await
        .map_err(|e| e.to_string())?
    }
}

/// Copy the CRI bind mounts referenced by `config.json` into the pod share so
/// the guest can materialize them into the container, and rewrite each such
/// mount's `source` to the guest-visible path under [`POD_SHARE_GUEST_MOUNT`].
///
/// Only real host-path bind mounts are copied — volumes and the generated
/// `/etc/resolv.conf`, `/etc/hosts`, `/etc/hostname`, termination-log, etc. The
/// virtual mounts in the spec (proc/sysfs/tmpfs/devpts/mqueue/cgroup) are left
/// untouched; the guest's default OCI spec provides those. Returns the rewritten
/// spec JSON. A source that doesn't exist on the host is skipped (left as-is).
fn materialize_bind_mounts(
    spec_json: &str,
    share_dir: &Path,
    id: &str,
    sandbox_hostname: Option<&str>,
    sandbox_sysctls: Option<&serde_json::Value>,
) -> Result<String, String> {
    let mut spec: serde_json::Value =
        serde_json::from_str(spec_json).map_err(|e| format!("parse config.json: {e}"))?;

    // Inject the pod hostname if the container spec doesn't carry one.
    if let Some(h) = sandbox_hostname {
        let empty = spec
            .get("hostname")
            .and_then(|v| v.as_str())
            .map(|s| s.is_empty())
            .unwrap_or(true);
        if empty {
            spec["hostname"] = serde_json::Value::String(h.to_string());
        }
    }

    // Merge the pod's IPC/UTS sysctls into the container spec (a container-specific
    // sysctl already present wins). crun sets them inside the container's own IPC
    // and UTS namespaces, which each pod container unshares. net.* sysctls are
    // deliberately excluded — the pod container declares no network namespace, so
    // crun would reject them; those are applied guest-wide at sandbox setup
    // instead (see `apply_guest_net_sysctls`), where the shared net namespace
    // makes them visible to every container.
    if let Some(serde_json::Value::Object(pod)) = sandbox_sysctls {
        let namespaced: Vec<(&String, &serde_json::Value)> =
            pod.iter().filter(|(k, _)| !k.starts_with("net.")).collect();
        if !namespaced.is_empty() {
            let target = spec
                .pointer_mut("/linux/sysctl")
                .and_then(|v| v.as_object_mut());
            match target {
                Some(existing) => {
                    for (k, v) in namespaced {
                        existing.entry(k.clone()).or_insert_with(|| v.clone());
                    }
                }
                None => {
                    let obj = namespaced
                        .into_iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect();
                    spec["linux"]["sysctl"] = serde_json::Value::Object(obj);
                }
            }
        }
    }

    let Some(mounts) = spec.get_mut("mounts").and_then(|m| m.as_array_mut()) else {
        return Ok(serde_json::to_string(&spec).unwrap_or_else(|_| spec_json.to_string()));
    };

    let mounts_dir = share_dir.join(id).join("mounts");
    let mut n = 0usize;
    for m in mounts.iter_mut() {
        let mtype = m.get("type").and_then(|t| t.as_str()).unwrap_or_default();
        let source = m
            .get("source")
            .and_then(|s| s.as_str())
            .unwrap_or_default()
            .to_string();
        let dest = m
            .get("destination")
            .and_then(|d| d.as_str())
            .unwrap_or_default();
        // A CRI bind mount is a real host path. Treat any mount whose source is an
        // existing absolute host path as one to materialize — some specs omit the
        // "bind" type and rely on options, and virtual mounts (proc/sysfs/tmpfs/
        // cgroup/mqueue/devpts) have non-path sources that won't exist as files.
        let is_virtual = matches!(
            mtype,
            "proc" | "sysfs" | "tmpfs" | "cgroup" | "cgroup2" | "mqueue" | "devpts" | "devtmpfs"
        );
        let exists = source.starts_with('/') && Path::new(&source).exists();
        debug!(
            "materialize_bind_mounts: mount type={mtype} source={source} dest={dest} virtual={is_virtual} exists={exists}"
        );
        if is_virtual || source.is_empty() || !exists {
            continue;
        }

        std::fs::create_dir_all(&mounts_dir)
            .map_err(|e| format!("mkdir {}: {e}", mounts_dir.display()))?;
        let dst = mounts_dir.join(n.to_string());
        // `cp -aT` makes `dst` a copy of `source` (file or dir), preserving
        // modes/owners/symlinks; reflink keeps it cheap on the same fs.
        let status = std::process::Command::new("cp")
            .args(["-aT", "--reflink=auto", &source])
            .arg(&dst)
            .status()
            .map_err(|e| format!("spawn cp for mount {source}: {e}"))?;
        if !status.success() {
            return Err(format!("copy mount {source}: cp exited {status}"));
        }

        // Make the copy world-readable/traversable so the guest agent can read it
        // through the (uid-mapped) virtiofs share regardless of the source's
        // original owner/mode — a CRI volume created root-only (e.g. mode 0700)
        // is otherwise EACCES to the guest. Container-visible perms only widen
        // read access on this ephemeral copy; write goes to the guest overlay.
        let _ = std::process::Command::new("chmod")
            .args(["-R", "a+rX"])
            .arg(&dst)
            .status();

        m["source"] = serde_json::Value::String(format!("{POD_SHARE_GUEST_MOUNT}/{id}/mounts/{n}"));
        n += 1;
    }

    serde_json::to_string(&spec).map_err(|e| format!("reserialize spec: {e}"))
}

/// Build a cgroups v1 `Metrics` message (the format containerd's CRI decodes for
/// `ContainerStats`) from a guest usage sample and serialize it. crun runs
/// cgroup-less in the guest, so only CPU total and memory usage are populated —
/// which is what the CRI cpu/memory stats surface.
fn encode_cgroup_metrics(cpu_ns: u64, mem_bytes: u64) -> Result<Vec<u8>, String> {
    use containerd_shim_protos::cgroups::metrics::{
        CPUStat, CPUUsage, MemoryEntry, MemoryStat, Metrics,
    };
    use containerd_shim_protos::protobuf::{Message, MessageField};

    let metrics = Metrics {
        cpu: MessageField::some(CPUStat {
            usage: MessageField::some(CPUUsage {
                total: cpu_ns,
                ..Default::default()
            }),
            ..Default::default()
        }),
        memory: MessageField::some(MemoryStat {
            usage: MessageField::some(MemoryEntry {
                usage: mem_bytes,
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };
    metrics
        .write_to_bytes()
        .map_err(|e| format!("encode cgroup metrics: {e}"))
}

// ======================= mock/engine runtime switch =========================

/// The backend the shim actually runs with, chosen at task-service creation:
/// `SMOLVM_SHIM_MOCK=1` keeps the in-process [`MockBackend`] (tests/smoke on
/// hosts without KVM); anything else drives real microVMs. An enum instead of
/// `dyn PodBackend` so `TaskService<B>` keeps its static dispatch.
pub enum ShimBackend {
    Mock(crate::backend::MockBackend),
    Engine(EnginePodBackend),
}

#[async_trait]
impl PodBackend for ShimBackend {
    async fn create_sandbox(
        &self,
        id: &str,
        bundle: &str,
        netns: Option<&str>,
    ) -> Result<u32, String> {
        match self {
            Self::Mock(b) => b.create_sandbox(id, bundle, netns).await,
            Self::Engine(b) => b.create_sandbox(id, bundle, netns).await,
        }
    }

    async fn create_container(&self, id: &str, spec: ProcessSpec) -> Result<u32, String> {
        match self {
            Self::Mock(b) => b.create_container(id, spec).await,
            Self::Engine(b) => b.create_container(id, spec).await,
        }
    }

    async fn start(&self, id: &str, exec_id: Option<&str>) -> Result<u32, String> {
        match self {
            Self::Mock(b) => b.start(id, exec_id).await,
            Self::Engine(b) => b.start(id, exec_id).await,
        }
    }

    async fn create_exec(&self, id: &str, exec_id: &str, spec: ProcessSpec) -> Result<(), String> {
        match self {
            Self::Mock(b) => b.create_exec(id, exec_id, spec).await,
            Self::Engine(b) => b.create_exec(id, exec_id, spec).await,
        }
    }

    async fn kill(
        &self,
        id: &str,
        exec_id: Option<&str>,
        signal: u32,
        all: bool,
    ) -> Result<(), String> {
        match self {
            Self::Mock(b) => b.kill(id, exec_id, signal, all).await,
            Self::Engine(b) => b.kill(id, exec_id, signal, all).await,
        }
    }

    async fn wait_channel(&self, id: &str, exec_id: Option<&str>) -> Result<ExitWatch, String> {
        match self {
            Self::Mock(b) => b.wait_channel(id, exec_id).await,
            Self::Engine(b) => b.wait_channel(id, exec_id).await,
        }
    }

    async fn resize_pty(
        &self,
        id: &str,
        exec_id: Option<&str>,
        w: u32,
        h: u32,
    ) -> Result<(), String> {
        match self {
            Self::Mock(b) => b.resize_pty(id, exec_id, w, h).await,
            Self::Engine(b) => b.resize_pty(id, exec_id, w, h).await,
        }
    }

    async fn close_io(&self, id: &str, exec_id: Option<&str>) -> Result<(), String> {
        match self {
            Self::Mock(b) => b.close_io(id, exec_id).await,
            Self::Engine(b) => b.close_io(id, exec_id).await,
        }
    }

    async fn delete(&self, id: &str, exec_id: Option<&str>) -> Result<(), String> {
        match self {
            Self::Mock(b) => b.delete(id, exec_id).await,
            Self::Engine(b) => b.delete(id, exec_id).await,
        }
    }

    async fn pids(&self, id: &str) -> Result<Vec<u32>, String> {
        match self {
            Self::Mock(b) => b.pids(id).await,
            Self::Engine(b) => b.pids(id).await,
        }
    }

    async fn stats(&self, id: &str) -> Result<Option<Vec<u8>>, String> {
        match self {
            Self::Mock(b) => b.stats(id).await,
            Self::Engine(b) => b.stats(id).await,
        }
    }
}
