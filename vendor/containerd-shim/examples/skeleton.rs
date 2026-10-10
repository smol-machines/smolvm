/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/
#[cfg(not(feature = "async"))]
use containerd_shim as shim;

#[cfg(not(feature = "async"))]
mod skeleton {
    use std::sync::Arc;

    use containerd_shim as shim;
    use log::info;
    use shim::{
        api, synchronous::publisher::RemotePublisher, Config, DeleteResponse, ExitSignal, Flags,
        TtrpcContext, TtrpcResult,
    };

    #[derive(Clone)]
    pub(crate) struct Service {
        exit: Arc<ExitSignal>,
    }

    impl shim::Shim for Service {
        type T = Service;

        fn new(_runtime_id: &str, _args: &Flags, _config: &mut Config) -> Self {
            Service {
                exit: Arc::new(ExitSignal::default()),
            }
        }

        fn start_shim(&mut self, opts: shim::StartOpts) -> Result<String, shim::Error> {
            let grouping = opts.id.clone();
            let (_child_id, address) = shim::spawn(opts, &grouping, Vec::new())?;
            Ok(address)
        }

        fn delete_shim(&mut self) -> Result<DeleteResponse, shim::Error> {
            Ok(DeleteResponse::new())
        }

        fn wait(&mut self) {
            self.exit.wait();
        }

        fn create_task_service(&self, _publisher: RemotePublisher) -> Self::T {
            self.clone()
        }
    }

    impl shim::Task for Service {
        fn connect(
            &self,
            _ctx: &TtrpcContext,
            _req: api::ConnectRequest,
        ) -> TtrpcResult<api::ConnectResponse> {
            info!("Connect request");
            Ok(api::ConnectResponse {
                version: String::from("example"),
                ..Default::default()
            })
        }

        fn shutdown(
            &self,
            _ctx: &TtrpcContext,
            _req: api::ShutdownRequest,
        ) -> TtrpcResult<api::Empty> {
            info!("Shutdown request");
            self.exit.signal();
            Ok(api::Empty::default())
        }
    }
}

fn main() {
    #[cfg(not(feature = "async"))]
    shim::run::<skeleton::Service>("io.containerd.empty.v1", None)
}
