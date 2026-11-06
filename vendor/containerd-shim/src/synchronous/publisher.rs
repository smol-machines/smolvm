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

//! Implements a client to publish events from the shim back to containerd.

use client::{
    protobuf::MessageDyn,
    shim::{event::Envelope, events},
    ttrpc::{self, context::Context},
    types::empty,
    Client, Events, EventsClient,
};
use containerd_shim_protos as client;

#[cfg(unix)]
use crate::util::connect;
#[cfg(target_os = "windows")] // Prevent unused warning.
use crate::Error;
use crate::{
    error::Result,
    util::{convert_to_any, timestamp},
};

#[cfg(windows)]
const RETRY_COUNT: i32 = 3;

/// Remote publisher connects to containerd's TTRPC endpoint to publish events from shim.
pub struct RemotePublisher {
    client: EventsClient,
}

impl RemotePublisher {
    /// Connect to containerd's TTRPC endpoint.
    ///
    /// containerd uses `/run/containerd/containerd.sock.ttrpc` by default
    pub fn new(address: impl AsRef<str>) -> Result<RemotePublisher> {
        let client = Self::connect(address)?;

        Ok(RemotePublisher {
            client: EventsClient::new(client),
        })
    }

    fn connect(address: impl AsRef<str>) -> Result<Client> {
        #[cfg(unix)]
        {
            let fd = connect(address)?;
            // Client::new() takes ownership of the RawFd.
            Client::new(fd).map_err(|err| err.into())
        }

        #[cfg(windows)]
        {
            for i in 0..RETRY_COUNT {
                match Client::connect(address.as_ref()) {
                    Ok(client) => return Ok(client),
                    Err(e) => match e {
                        ttrpc::Error::Windows(231) => {
                            // ERROR_PIPE_BUSY
                            log::debug!("pipe busy during connect. try number {}", i);
                            std::thread::sleep(std::time::Duration::from_millis(5));
                        }
                        _ => return Err(e.into()),
                    },
                }
            }
            Err(other!("failed to connect to {}", address.as_ref()))
        }
    }

    /// Publish a new event.
    ///
    /// Event object can be anything that Protobuf able serialize (e.g. implement `Message` trait).
    pub fn publish(
        &self,
        ctx: Context,
        topic: &str,
        namespace: &str,
        event: Box<dyn MessageDyn>,
    ) -> Result<()> {
        let mut envelope = Envelope::new();
        envelope.set_topic(topic.to_owned());
        envelope.set_namespace(namespace.to_owned());
        envelope.set_timestamp(timestamp()?);
        envelope.set_event(convert_to_any(event)?);

        let mut req = events::ForwardRequest::new();
        req.set_envelope(envelope);

        self.client.forward(ctx, &req)?;

        Ok(())
    }
}

impl Events for RemotePublisher {
    fn forward(
        &self,
        _ctx: &ttrpc::TtrpcContext,
        req: events::ForwardRequest,
    ) -> ttrpc::Result<empty::Empty> {
        self.client.forward(Context::default(), &req)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use client::{
        api::{Empty, ForwardRequest},
        events::task::TaskOOM,
    };
    use ttrpc::Server;

    use super::*;
    #[cfg(windows)]
    use crate::synchronous::wait_socket_working;

    struct FakeServer {}

    impl Events for FakeServer {
        fn forward(&self, _ctx: &ttrpc::TtrpcContext, req: ForwardRequest) -> ttrpc::Result<Empty> {
            let env = req.envelope();
            assert_eq!(env.topic(), "/tasks/oom");
            Ok(Empty::default())
        }
    }

    #[test]
    fn test_connect() {
        #[cfg(unix)]
        let tmpdir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        let path = format!("{}/socket", tmpdir.as_ref().to_str().unwrap());
        #[cfg(windows)]
        let path = "\\\\.\\pipe\\test-pipe".to_string();
        let path1 = path.clone();

        assert!(RemotePublisher::connect("a".repeat(16384)).is_err());
        assert!(RemotePublisher::connect(&path).is_err());

        let barrier = Arc::new(Barrier::new(2));
        let barrier2 = barrier.clone();
        let thread = std::thread::spawn(move || {
            let mut server = create_server(&path1);

            server.start().unwrap();

            #[cfg(windows)]
            // make sure pipe is ready on windows
            wait_socket_working(&path1, 5, 5).unwrap();

            barrier2.wait();

            barrier2.wait();
            server.shutdown();
        });

        barrier.wait();
        let client = RemotePublisher::new(&path).unwrap();
        let mut msg = TaskOOM::new();
        msg.set_container_id("test".to_string());
        client
            .publish(Context::default(), "/tasks/oom", "ns1", Box::new(msg))
            .unwrap();
        barrier.wait();

        thread.join().unwrap();
    }

    fn create_server(server_address: &str) -> Server {
        #[cfg(unix)]
        {
            use std::os::unix::{io::AsRawFd, net::UnixListener};
            let listener = UnixListener::bind(server_address).unwrap();
            listener.set_nonblocking(true).unwrap();
            let task = Box::new(FakeServer {}) as Box<dyn Events + Send + Sync>;
            let service = client::create_events(task.into());
            let server = Server::new()
                .add_listener(listener.as_raw_fd())
                .unwrap()
                .register_service(service);
            std::mem::forget(listener);
            server
        }

        #[cfg(windows)]
        {
            let service = client::create_events(Arc::new(FakeServer {}));

            Server::new()
                .bind(server_address)
                .unwrap()
                .register_service(service)
        }
    }
}
