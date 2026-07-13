//! The shim v2 Task service: containerd's per-pod state machine.
//!
//! Holds the sandbox + container process table and enforces the lifecycle
//! containerd/critest expect (Created → Running → Stopped, exactly-once exit
//! events, Wait blocking until exit, Delete returning exit info), delegating
//! VM mechanics to a [`PodBackend`].

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use containerd_shim::publisher::RemotePublisher;
use containerd_shim::util::{convert_to_any, timestamp};
use containerd_shim::TtrpcResult;
use containerd_shim_protos::api;
use containerd_shim_protos::events::task::{
    TaskCreate, TaskDelete, TaskExecAdded, TaskExecStarted, TaskExit, TaskOOM, TaskStart,
};
use containerd_shim_protos::protobuf::well_known_types::timestamp::Timestamp;
use containerd_shim_protos::protobuf::{Message, MessageDyn};
use containerd_shim_protos::shim_async::Task;
use containerd_shim_protos::ttrpc::r#async::TtrpcContext;
use log::{debug, warn};
use tokio::sync::Mutex;

use crate::backend::{ExitInfo, PodBackend, ProcessSpec, Stdio};
use crate::bundle;

fn err(msg: impl std::fmt::Display) -> containerd_shim_protos::ttrpc::Error {
    containerd_shim_protos::ttrpc::Error::RpcStatus(containerd_shim_protos::ttrpc::get_status(
        containerd_shim_protos::ttrpc::Code::UNKNOWN,
        msg.to_string(),
    ))
}

fn not_found(msg: impl std::fmt::Display) -> containerd_shim_protos::ttrpc::Error {
    containerd_shim_protos::ttrpc::Error::RpcStatus(containerd_shim_protos::ttrpc::get_status(
        containerd_shim_protos::ttrpc::Code::NOT_FOUND,
        msg.to_string(),
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcState {
    Created,
    Running,
    Stopped,
}

struct Proc {
    state: ProcState,
    pid: u32,
    stdio: Stdio,
    exit: Option<ExitInfo>,
    is_sandbox: bool,
    bundle: String,
}

/// `(container_id, exec_id)` → process entry. Empty exec_id = init process.
type ProcKey = (String, String);

pub struct TaskService<B: PodBackend> {
    backend: Arc<B>,
    procs: Arc<Mutex<HashMap<ProcKey, Proc>>>,
    publisher: Option<Arc<RemotePublisher>>,
    namespace: String,
    exit: Arc<containerd_shim::asynchronous::ExitSignal>,
}

impl<B: PodBackend> Clone for TaskService<B> {
    fn clone(&self) -> Self {
        Self {
            backend: self.backend.clone(),
            procs: self.procs.clone(),
            publisher: self.publisher.clone(),
            namespace: self.namespace.clone(),
            exit: self.exit.clone(),
        }
    }
}

impl<B: PodBackend> TaskService<B> {
    pub fn new(
        backend: Arc<B>,
        publisher: Option<Arc<RemotePublisher>>,
        namespace: String,
        exit: Arc<containerd_shim::asynchronous::ExitSignal>,
    ) -> Self {
        Self {
            backend,
            procs: Arc::new(Mutex::new(HashMap::new())),
            publisher,
            namespace,
            exit,
        }
    }

    async fn publish(&self, topic: &str, event: Box<dyn MessageDyn>) {
        if let Some(p) = &self.publisher {
            let ctx = containerd_shim_protos::ttrpc::context::Context::default();
            if let Err(e) = p.publish(ctx, topic, &self.namespace, event).await {
                warn!("publish {topic} failed: {e}");
            }
        }
    }

    /// Spawn the exit-watcher for a started process: on exit, mark Stopped and
    /// publish TaskExit exactly once.
    async fn watch_exit(&self, id: String, exec_id: String, pid: u32) {
        let backend = self.backend.clone();
        let procs = self.procs.clone();
        let this = self.clone();
        let exec_opt = if exec_id.is_empty() {
            None
        } else {
            Some(exec_id.clone())
        };
        tokio::spawn(async move {
            let mut rx = match backend.wait_channel(&id, exec_opt.as_deref()).await {
                Ok(rx) => rx,
                Err(e) => {
                    warn!("wait_channel({id},{exec_id}): {e}");
                    return;
                }
            };
            let info = loop {
                if let Some(info) = *rx.borrow() {
                    break info;
                }
                if rx.changed().await.is_err() {
                    // Backend dropped: treat as exit 255 now.
                    break ExitInfo {
                        status: 255,
                        exited_at_ns: 0,
                        oom: false,
                    };
                }
            };
            {
                let mut map = procs.lock().await;
                if let Some(p) = map.get_mut(&(id.clone(), exec_id.clone())) {
                    if p.state == ProcState::Stopped {
                        return; // already reported
                    }
                    p.state = ProcState::Stopped;
                    p.exit = Some(info);
                }
            }
            // A cgroup OOM kill must be announced before the exit so the CRI
            // has marked the container OOMKilled by the time it reads the exit
            // status. Only the init process (empty exec_id) carries this.
            if info.oom && exec_id.is_empty() {
                let mut oom = TaskOOM::new();
                oom.container_id = id.clone();
                this.publish("/tasks/oom", Box::new(oom)).await;
            }
            let mut ev = TaskExit::new();
            ev.container_id = id.clone();
            ev.id = if exec_id.is_empty() {
                id.clone()
            } else {
                exec_id.clone()
            };
            ev.pid = pid;
            ev.exit_status = info.status;
            ev.exited_at = Some(protobuf_ts(info.exited_at_ns)).into();
            this.publish("/tasks/exit", Box::new(ev)).await;
        });
    }
}

fn protobuf_ts(ns: i64) -> Timestamp {
    if ns <= 0 {
        return timestamp().unwrap_or_default();
    }
    let mut t = Timestamp::new();
    t.seconds = ns / 1_000_000_000;
    t.nanos = (ns % 1_000_000_000) as i32;
    t
}

fn state_to_api(s: ProcState) -> api::Status {
    match s {
        ProcState::Created => api::Status::CREATED,
        ProcState::Running => api::Status::RUNNING,
        ProcState::Stopped => api::Status::STOPPED,
    }
}

#[async_trait]
impl<B: PodBackend> Task for TaskService<B> {
    async fn create(
        &self,
        _ctx: &TtrpcContext,
        req: api::CreateTaskRequest,
    ) -> TtrpcResult<api::CreateTaskResponse> {
        let id = req.id.clone();
        debug!("create task id={id} bundle={}", req.bundle);
        let info = bundle::load(&req.bundle).map_err(err)?;

        let stdio = Stdio {
            stdin: req.stdin.clone(),
            stdout: req.stdout.clone(),
            stderr: req.stderr.clone(),
            terminal: req.terminal,
        };

        let pid = if info.is_sandbox {
            self.backend
                .create_sandbox(&id, &req.bundle, info.netns.as_deref())
                .await
                .map_err(err)?
        } else {
            // Mount containerd's rootfs mounts at bundle/rootfs, then hand the
            // host path to the backend for guest sharing.
            let rootfs = bundle::mount_rootfs(&req.bundle, &req.rootfs)
                .await
                .map_err(err)?;
            self.backend
                .create_container(
                    &id,
                    ProcessSpec {
                        bundle: req.bundle.clone(),
                        rootfs,
                        stdio: stdio.clone(),
                        exec_spec: None,
                    },
                )
                .await
                .map_err(err)?
        };

        let mut map = self.procs.lock().await;
        if map.contains_key(&(id.clone(), String::new())) {
            return Err(err(format!("task {id} already exists")));
        }
        map.insert(
            (id.clone(), String::new()),
            Proc {
                state: ProcState::Created,
                pid,
                stdio,
                exit: None,
                is_sandbox: info.is_sandbox,
                bundle: req.bundle.clone(),
            },
        );
        drop(map);

        let mut ev = TaskCreate::new();
        ev.container_id = id.clone();
        ev.bundle = req.bundle.clone();
        ev.pid = pid;
        self.publish("/tasks/create", Box::new(ev)).await;

        Ok(api::CreateTaskResponse {
            pid,
            ..Default::default()
        })
    }

    async fn start(
        &self,
        _ctx: &TtrpcContext,
        req: api::StartRequest,
    ) -> TtrpcResult<api::StartResponse> {
        let (id, exec_id) = (req.id.clone(), req.exec_id.clone());
        let exec_opt = if exec_id.is_empty() {
            None
        } else {
            Some(exec_id.as_str())
        };
        let pid = self.backend.start(&id, exec_opt).await.map_err(err)?;
        {
            let mut map = self.procs.lock().await;
            let p = map
                .get_mut(&(id.clone(), exec_id.clone()))
                .ok_or_else(|| not_found(format!("process {id}/{exec_id}")))?;
            p.state = ProcState::Running;
            p.pid = pid;
        }
        self.watch_exit(id.clone(), exec_id.clone(), pid).await;

        if exec_id.is_empty() {
            let mut ev = TaskStart::new();
            ev.container_id = id.clone();
            ev.pid = pid;
            self.publish("/tasks/start", Box::new(ev)).await;
        } else {
            let mut ev = TaskExecStarted::new();
            ev.container_id = id.clone();
            ev.exec_id = exec_id.clone();
            ev.pid = pid;
            self.publish("/tasks/exec-started", Box::new(ev)).await;
        }
        Ok(api::StartResponse {
            pid,
            ..Default::default()
        })
    }

    async fn state(
        &self,
        _ctx: &TtrpcContext,
        req: api::StateRequest,
    ) -> TtrpcResult<api::StateResponse> {
        let map = self.procs.lock().await;
        let p = map
            .get(&(req.id.clone(), req.exec_id.clone()))
            .ok_or_else(|| not_found(format!("process {}/{}", req.id, req.exec_id)))?;
        let mut resp = api::StateResponse {
            id: req.id.clone(),
            pid: p.pid,
            bundle: p.bundle.clone(),
            stdin: p.stdio.stdin.clone(),
            stdout: p.stdio.stdout.clone(),
            stderr: p.stdio.stderr.clone(),
            terminal: p.stdio.terminal,
            exit_status: p.exit.map(|e| e.status).unwrap_or_default(),
            ..Default::default()
        };
        resp.set_status(state_to_api(p.state));
        if let Some(e) = p.exit {
            resp.exited_at = Some(protobuf_ts(e.exited_at_ns)).into();
        }
        Ok(resp)
    }

    async fn wait(
        &self,
        _ctx: &TtrpcContext,
        req: api::WaitRequest,
    ) -> TtrpcResult<api::WaitResponse> {
        let exec_opt = if req.exec_id.is_empty() {
            None
        } else {
            Some(req.exec_id.as_str())
        };
        // Already exited? (Delete-after-exit races.)
        {
            let map = self.procs.lock().await;
            if let Some(p) = map.get(&(req.id.clone(), req.exec_id.clone())) {
                if let Some(e) = p.exit {
                    return Ok(api::WaitResponse {
                        exit_status: e.status,
                        exited_at: Some(protobuf_ts(e.exited_at_ns)).into(),
                        ..Default::default()
                    });
                }
            } else {
                return Err(not_found(format!("process {}/{}", req.id, req.exec_id)));
            }
        }
        let mut rx = self
            .backend
            .wait_channel(&req.id, exec_opt)
            .await
            .map_err(err)?;
        let info = loop {
            if let Some(info) = *rx.borrow() {
                break info;
            }
            if rx.changed().await.is_err() {
                break ExitInfo {
                    status: 255,
                    exited_at_ns: 0,
                    oom: false,
                };
            }
        };
        Ok(api::WaitResponse {
            exit_status: info.status,
            exited_at: Some(protobuf_ts(info.exited_at_ns)).into(),
            ..Default::default()
        })
    }

    async fn kill(&self, _ctx: &TtrpcContext, req: api::KillRequest) -> TtrpcResult<api::Empty> {
        let exec_opt = if req.exec_id.is_empty() {
            None
        } else {
            Some(req.exec_id.as_str())
        };
        {
            let map = self.procs.lock().await;
            let p = map
                .get(&(req.id.clone(), req.exec_id.clone()))
                .ok_or_else(|| not_found(format!("process {}/{}", req.id, req.exec_id)))?;
            if p.state == ProcState::Stopped {
                // Killing an exited process is a no-op (matches runc shim).
                return Ok(api::Empty::default());
            }
        }
        self.backend
            .kill(&req.id, exec_opt, req.signal, req.all)
            .await
            .map_err(err)?;
        Ok(api::Empty::default())
    }

    async fn exec(
        &self,
        _ctx: &TtrpcContext,
        req: api::ExecProcessRequest,
    ) -> TtrpcResult<api::Empty> {
        let spec = ProcessSpec {
            bundle: String::new(),
            rootfs: String::new(),
            stdio: Stdio {
                stdin: req.stdin.clone(),
                stdout: req.stdout.clone(),
                stderr: req.stderr.clone(),
                terminal: req.terminal,
            },
            exec_spec: Some(req.spec.value.clone()),
        };
        {
            let map = self.procs.lock().await;
            if !map.contains_key(&(req.id.clone(), String::new())) {
                return Err(not_found(format!("container {}", req.id)));
            }
            if map.contains_key(&(req.id.clone(), req.exec_id.clone())) {
                return Err(err(format!("exec {} already exists", req.exec_id)));
            }
        }
        self.backend
            .create_exec(&req.id, &req.exec_id, spec.clone())
            .await
            .map_err(err)?;
        self.procs.lock().await.insert(
            (req.id.clone(), req.exec_id.clone()),
            Proc {
                state: ProcState::Created,
                pid: 0,
                stdio: spec.stdio,
                exit: None,
                is_sandbox: false,
                bundle: String::new(),
            },
        );
        let mut ev = TaskExecAdded::new();
        ev.container_id = req.id.clone();
        ev.exec_id = req.exec_id.clone();
        self.publish("/tasks/exec-added", Box::new(ev)).await;
        Ok(api::Empty::default())
    }

    async fn resize_pty(
        &self,
        _ctx: &TtrpcContext,
        req: api::ResizePtyRequest,
    ) -> TtrpcResult<api::Empty> {
        let exec_opt = if req.exec_id.is_empty() {
            None
        } else {
            Some(req.exec_id.as_str())
        };
        self.backend
            .resize_pty(&req.id, exec_opt, req.width, req.height)
            .await
            .map_err(err)?;
        Ok(api::Empty::default())
    }

    async fn close_io(
        &self,
        _ctx: &TtrpcContext,
        req: api::CloseIORequest,
    ) -> TtrpcResult<api::Empty> {
        let exec_opt = if req.exec_id.is_empty() {
            None
        } else {
            Some(req.exec_id.as_str())
        };
        self.backend
            .close_io(&req.id, exec_opt)
            .await
            .map_err(err)?;
        Ok(api::Empty::default())
    }

    async fn delete(
        &self,
        _ctx: &TtrpcContext,
        req: api::DeleteRequest,
    ) -> TtrpcResult<api::DeleteResponse> {
        let exec_opt = if req.exec_id.is_empty() {
            None
        } else {
            Some(req.exec_id.as_str())
        };
        let (pid, mut exit, bundle_dir, is_sandbox) = {
            let map = self.procs.lock().await;
            let p = map
                .get(&(req.id.clone(), req.exec_id.clone()))
                .ok_or_else(|| not_found(format!("process {}/{}", req.id, req.exec_id)))?;
            (p.pid, p.exit, p.bundle.clone(), p.is_sandbox)
        };
        // The exit-watcher records exits asynchronously; if Delete arrives
        // first, read the backend's exit channel directly so the response
        // still carries the real status.
        if exit.is_none() {
            if let Ok(rx) = self.backend.wait_channel(&req.id, exec_opt).await {
                exit = *rx.borrow();
            }
        }
        self.backend.delete(&req.id, exec_opt).await.map_err(err)?;
        self.procs
            .lock()
            .await
            .remove(&(req.id.clone(), req.exec_id.clone()));

        // Unmount the bundle rootfs for workload init processes (best-effort;
        // the sandbox never mounted one).
        if req.exec_id.is_empty() && !is_sandbox && !bundle_dir.is_empty() {
            bundle::unmount_rootfs(&bundle_dir).await;
        }

        let exited_at = exit
            .map(|e| protobuf_ts(e.exited_at_ns))
            .unwrap_or_default();
        if req.exec_id.is_empty() {
            let mut ev = TaskDelete::new();
            ev.container_id = req.id.clone();
            ev.pid = pid;
            ev.exit_status = exit.map(|e| e.status).unwrap_or_default();
            ev.exited_at = Some(exited_at.clone()).into();
            self.publish("/tasks/delete", Box::new(ev)).await;
        }
        Ok(api::DeleteResponse {
            pid,
            exit_status: exit.map(|e| e.status).unwrap_or_default(),
            exited_at: Some(exited_at).into(),
            ..Default::default()
        })
    }

    async fn pids(
        &self,
        _ctx: &TtrpcContext,
        req: api::PidsRequest,
    ) -> TtrpcResult<api::PidsResponse> {
        let pids = self.backend.pids(&req.id).await.map_err(err)?;
        let processes = pids
            .into_iter()
            .map(|pid| containerd_shim_protos::types::task::ProcessInfo {
                pid,
                ..Default::default()
            })
            .collect();
        Ok(api::PidsResponse {
            processes,
            ..Default::default()
        })
    }

    async fn stats(
        &self,
        _ctx: &TtrpcContext,
        req: api::StatsRequest,
    ) -> TtrpcResult<api::StatsResponse> {
        let blob = self.backend.stats(&req.id).await.map_err(err)?;
        let mut resp = api::StatsResponse::default();
        if let Some(bytes) = blob {
            // The backend hands us an encoded cgroups Metrics message.
            let metrics =
                containerd_shim_protos::cgroups::metrics::Metrics::parse_from_bytes(&bytes)
                    .map_err(err)?;
            resp.stats = Some(convert_to_any(Box::new(metrics)).map_err(err)?).into();
        }
        Ok(resp)
    }

    async fn connect(
        &self,
        _ctx: &TtrpcContext,
        req: api::ConnectRequest,
    ) -> TtrpcResult<api::ConnectResponse> {
        let map = self.procs.lock().await;
        let pid = map
            .get(&(req.id.clone(), String::new()))
            .map(|p| p.pid)
            .unwrap_or_default();
        Ok(api::ConnectResponse {
            shim_pid: std::process::id(),
            task_pid: pid,
            ..Default::default()
        })
    }

    async fn shutdown(
        &self,
        _ctx: &TtrpcContext,
        _req: api::ShutdownRequest,
    ) -> TtrpcResult<api::Empty> {
        let map = self.procs.lock().await;
        if map.is_empty() {
            self.exit.signal();
        }
        Ok(api::Empty::default())
    }

    async fn update(
        &self,
        _ctx: &TtrpcContext,
        _req: api::UpdateTaskRequest,
    ) -> TtrpcResult<api::Empty> {
        // Resource updates inside the guest: accepted as no-op for now (the
        // guest cgroup follows the container spec set at create time).
        Ok(api::Empty::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MockBackend;

    fn svc(backend: Arc<MockBackend>) -> TaskService<MockBackend> {
        TaskService::new(
            backend,
            None,
            "k8s.io".into(),
            Arc::new(containerd_shim::asynchronous::ExitSignal::default()),
        )
    }

    fn ttctx() -> TtrpcContext {
        TtrpcContext {
            mh: Default::default(),
            metadata: Default::default(),
            timeout_nano: 0,
        }
    }

    async fn create_container(
        s: &TaskService<MockBackend>,
        dir: &std::path::Path,
        id: &str,
    ) -> api::CreateTaskResponse {
        let bundle = dir.join(id);
        std::fs::create_dir_all(bundle.join("rootfs")).unwrap();
        std::fs::write(
            bundle.join("config.json"),
            serde_json::json!({
                "ociVersion": "1.0.2",
                "process": {"args": ["sleep", "1"], "cwd": "/"},
                "root": {"path": "rootfs"},
                "annotations": {"io.kubernetes.cri.container-type": "container"}
            })
            .to_string(),
        )
        .unwrap();
        let req = api::CreateTaskRequest {
            id: id.to_string(),
            bundle: bundle.to_string_lossy().into_owned(),
            ..Default::default()
        };
        s.create(&ttctx(), req).await.unwrap()
    }

    #[tokio::test]
    async fn lifecycle_create_start_kill_wait_delete() {
        let backend = MockBackend::new();
        let s = svc(backend.clone());
        let dir = tempfile::tempdir().unwrap();

        let created = create_container(&s, dir.path(), "c1").await;
        assert_eq!(created.pid, 100);

        // State: CREATED
        let st = s
            .state(
                &ttctx(),
                api::StateRequest {
                    id: "c1".into(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(st.status.unwrap(), api::Status::CREATED);

        // Start → RUNNING
        s.start(
            &ttctx(),
            api::StartRequest {
                id: "c1".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        // Kill(SIGKILL) → exit 137; Wait resolves
        s.kill(
            &ttctx(),
            api::KillRequest {
                id: "c1".into(),
                signal: 9,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let w = s
            .wait(
                &ttctx(),
                api::WaitRequest {
                    id: "c1".into(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(w.exit_status, 137);

        // Delete returns the same exit info
        let d = s
            .delete(
                &ttctx(),
                api::DeleteRequest {
                    id: "c1".into(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(d.exit_status, 137);

        // Gone afterwards
        assert!(s
            .state(
                &ttctx(),
                api::StateRequest {
                    id: "c1".into(),
                    ..Default::default()
                },
            )
            .await
            .is_err());
    }

    #[tokio::test]
    async fn exec_lifecycle() {
        let backend = MockBackend::new();
        let s = svc(backend.clone());
        let dir = tempfile::tempdir().unwrap();
        create_container(&s, dir.path(), "c2").await;
        s.start(
            &ttctx(),
            api::StartRequest {
                id: "c2".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let mut ereq = api::ExecProcessRequest {
            id: "c2".into(),
            exec_id: "e1".into(),
            ..Default::default()
        };
        ereq.spec =
            Some(containerd_shim_protos::protobuf::well_known_types::any::Any::default()).into();
        s.exec(&ttctx(), ereq).await.unwrap();

        let started = s
            .start(
                &ttctx(),
                api::StartRequest {
                    id: "c2".into(),
                    exec_id: "e1".into(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(started.pid, 200);

        backend.finish("c2", Some("e1"), 0).await;
        let w = s
            .wait(
                &ttctx(),
                api::WaitRequest {
                    id: "c2".into(),
                    exec_id: "e1".into(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(w.exit_status, 0);
    }

    #[tokio::test]
    async fn wait_after_exit_returns_immediately() {
        let backend = MockBackend::new();
        let s = svc(backend.clone());
        let dir = tempfile::tempdir().unwrap();
        create_container(&s, dir.path(), "c3").await;
        s.start(
            &ttctx(),
            api::StartRequest {
                id: "c3".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        backend.finish("c3", None, 7).await;
        // Give the watcher a beat to record the exit.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let w = s
            .wait(
                &ttctx(),
                api::WaitRequest {
                    id: "c3".into(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(w.exit_status, 7);
        let st = s
            .state(
                &ttctx(),
                api::StateRequest {
                    id: "c3".into(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(st.status.unwrap(), api::Status::STOPPED);
    }
}
