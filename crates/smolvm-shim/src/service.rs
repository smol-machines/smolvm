//! Shim v2 process lifecycle: what containerd invokes to start/stop the shim
//! itself. One shim process serves one pod (grouped by task id).

use std::sync::Arc;

use async_trait::async_trait;
use containerd_shim::asynchronous::{run, spawn, ExitSignal, Shim};
use containerd_shim::publisher::RemotePublisher;
use containerd_shim::util::timestamp;
use containerd_shim::{Config, Error, Flags, StartOpts};
use containerd_shim_protos::api::DeleteResponse;
use log::warn;

use crate::backend::MockBackend;
use crate::engine::{EnginePodBackend, ShimBackend};
use crate::task::TaskService;

pub const RUNTIME_ID: &str = "io.containerd.smolvm.v2";

pub struct Service {
    exit: Arc<ExitSignal>,
    namespace: String,
    /// Task id containerd invoked us with. For the sandbox shim this is the
    /// sandbox id, which is also the persistent machine's name — used by
    /// `delete_shim` to reap a leaked VM after a shim crash.
    id: String,
}

#[async_trait]
impl Shim for Service {
    // Engine-backed by default (real microVMs); SMOLVM_SHIM_MOCK=1 keeps the
    // in-process mock so tests/smoke runs work on hosts without KVM.
    type T = TaskService<ShimBackend>;

    async fn new(_runtime_id: &str, args: &Flags, _config: &mut Config) -> Self {
        Service {
            exit: Arc::new(ExitSignal::default()),
            namespace: args.namespace.clone(),
            id: args.id.clone(),
        }
    }

    async fn start_shim(&mut self, opts: StartOpts) -> Result<String, Error> {
        let grouping = opts.id.clone();
        let address = spawn(opts, &grouping, Vec::new()).await?;
        Ok(address)
    }

    async fn delete_shim(&mut self) -> Result<DeleteResponse, Error> {
        // Recovery cleanup: containerd invokes the shim binary's `delete` action
        // to reap a shim whose process is already gone (crash, force-delete). The
        // sandbox VM is a persistent machine named after the sandbox id and would
        // otherwise leak, so tear it down here. The runtime reads its machine
        // state from disk, so a fresh process can still find and kill the VM.
        // Best-effort — a missing machine (a container-task delete, or a VM
        // already cleaned by the graceful path) is not an error.
        let id = self.id.clone();
        let _ = tokio::task::spawn_blocking(move || match smolvm::embedded::runtime() {
            Ok(rt) => {
                if let Err(e) = rt.delete_machine(&id) {
                    warn!("delete_shim: reaping VM {id} failed (may already be gone): {e}");
                }
            }
            Err(e) => warn!("delete_shim: runtime unavailable, cannot reap VM {id}: {e}"),
        })
        .await;
        Ok(DeleteResponse {
            exit_status: 137,
            exited_at: Some(timestamp()?).into(),
            ..Default::default()
        })
    }

    async fn wait(&mut self) {
        self.exit.wait().await;
    }

    async fn create_task_service(&self, publisher: RemotePublisher) -> Self::T {
        let backend = if std::env::var("SMOLVM_SHIM_MOCK").as_deref() == Ok("1") {
            warn!("SMOLVM_SHIM_MOCK=1: using mock backend (no VMs will boot)");
            ShimBackend::Mock(MockBackend::default())
        } else {
            ShimBackend::Engine(EnginePodBackend::new())
        };
        TaskService::new(
            Arc::new(backend),
            Some(Arc::new(publisher)),
            self.namespace.clone(),
            self.exit.clone(),
        )
    }
}

pub fn run_shim() {
    let body = async {
        run::<Service>(RUNTIME_ID, None).await;
    };
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(body);
}
