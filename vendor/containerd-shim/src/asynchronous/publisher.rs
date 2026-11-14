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

use std::os::unix::io::RawFd;

use async_trait::async_trait;
use containerd_shim_protos::{
    api::Empty,
    protobuf::MessageDyn,
    shim::{event::Envelope, events},
    shim_async::{Client, Events, EventsClient},
    ttrpc,
    ttrpc::{context::Context, r#async::TtrpcContext},
};
use log::{debug, error, warn};
use tokio::sync::mpsc;

use crate::{
    error::{self, Result},
    util::{asyncify, connect, convert_to_any, timestamp},
};

/// The publisher reports events and uses a queue to retry the event reporting.
/// The maximum number of attempts to report is 5 times.
/// When the ttrpc client fails to report, it attempts to reconnect to the client and report.
///
/// Max queue size
const QUEUE_SIZE: i64 = 1024;
/// Max try five times
const MAX_REQUEUE: i64 = 5;

/// Async Remote publisher connects to containerd's TTRPC endpoint to publish events from shim.
pub struct RemotePublisher {
    pub address: String,
    sender: mpsc::Sender<Item>,
}

#[derive(Clone, Debug)]
pub struct Item {
    ev: Envelope,
    ctx: Context,
    count: i64,
}

impl RemotePublisher {
    /// Connect to containerd's TTRPC endpoint asynchronously.
    ///
    /// containerd uses `/run/containerd/containerd.sock.ttrpc` by default
    pub async fn new(address: impl AsRef<str>) -> Result<RemotePublisher> {
        let client = Self::connect(address.as_ref()).await?;
        // Init the queue channel
        let (sender, receiver) = mpsc::channel::<Item>(QUEUE_SIZE as usize);
        let rt = RemotePublisher {
            address: address.as_ref().to_string(),
            sender,
        };
        rt.process_queue(client, receiver).await;
        Ok(rt)
    }

    /// Process_queue for push events
    ///
    /// This is a loop task for dealing event tasks
    pub async fn process_queue(&self, ttrpc_client: Client, mut receiver: mpsc::Receiver<Item>) {
        let mut client = EventsClient::new(ttrpc_client);
        let sender = self.sender.clone();
        let address = self.address.clone();
        tokio::spawn(async move {
            // only this use receiver
            while let Some(item) = receiver.recv().await {
                // drop this event after MAX_REQUEUE try
                if item.count > MAX_REQUEUE {
                    debug!("drop event {:?}", item);
                    continue;
                }
                let mut req = events::ForwardRequest::new();
                req.set_envelope(item.ev.clone());
                let new_item = Item {
                    ev: item.ev.clone(),
                    ctx: item.ctx.clone(),
                    count: item.count + 1,
                };
                if let Err(e) = client.forward(new_item.ctx.clone(), &req).await {
                    match e {
                        ttrpc::error::Error::RemoteClosed | ttrpc::error::Error::LocalClosed => {
                            warn!("publish fail because the server or client close {:?}", e);
                            // reconnect client
                            if let Ok(c) = Self::connect(address.as_str()).await.map_err(|e| {
                                debug!("reconnect the ttrpc client {:?} fail", e);
                            }) {
                                client = EventsClient::new(c);
                            }
                        }
                        _ => {
                            // TODO! if it is other error , May we should deal with socket file
                            error!("the client forward err is {:?}", e);
                        }
                    }
                    let sender_ref = sender.clone();
                    // Take a another task requeue , for no blocking the recv task
                    tokio::spawn(async move {
                        // wait for few time and send for imporving the success ratio
                        tokio::time::sleep(tokio::time::Duration::from_secs(new_item.count as u64))
                            .await;
                        // if channel is full and send fail ,release it after 3 seconds
                        let _ = sender_ref
                            .send_timeout(new_item, tokio::time::Duration::from_secs(3))
                            .await;
                    });
                }
            }
            debug!("publisher 'process_queue' quit complete");
        });
    }

    async fn connect(address: impl AsRef<str>) -> Result<Client> {
        let addr = address.as_ref().to_string();
        let fd = asyncify(move || -> Result<RawFd> {
            let fd = connect(addr)?;
            Ok(fd)
        })
        .await?;

        // Safety: `fd` is a unix socket returned by `connect()`.
        // `from_raw_unix_socket_fd` takes ownership of the RawFd.
        Ok(unsafe { Client::from_raw_unix_socket_fd(fd) })
    }

    /// Publish a new event.
    ///
    /// Event object can be anything that Protobuf able serialize (e.g. implement `Message` trait).
    pub async fn publish(
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

        let item = Item {
            ev: envelope.clone(),
            ctx: ctx.clone(),
            count: 0,
        };

        //if channel is full and send fail ,release it after 3 seconds
        self.sender
            .send_timeout(item, tokio::time::Duration::from_secs(3))
            .await
            .map_err(|e| error::Error::Ttrpc(ttrpc::error::Error::Others(e.to_string())))?;

        Ok(())
    }
}

#[async_trait]
impl Events for RemotePublisher {
    async fn forward(
        &self,
        _ctx: &TtrpcContext,
        req: events::ForwardRequest,
    ) -> ttrpc::Result<Empty> {
        let item = Item {
            ev: req.envelope().clone(),
            ctx: Context::default(),
            count: 0,
        };

        //if channel is full and send fail ,release it after 3 seconds
        self.sender
            .send_timeout(item, tokio::time::Duration::from_secs(3))
            .await
            .map_err(|e| error::Error::Ttrpc(ttrpc::error::Error::Others(e.to_string())))?;

        Ok(Empty::default())
    }
}

#[cfg(test)]
mod tests {
    use std::{os::unix::net::UnixListener, sync::Arc};

    use async_trait::async_trait;
    use containerd_shim_protos::{
        api::{Empty, ForwardRequest},
        events::task::TaskOOM,
        shim_async::{create_events, Events},
        ttrpc::asynchronous::{transport::Listener, Server},
    };
    use tokio::sync::{
        mpsc::{channel, Sender},
        Barrier,
    };

    use super::*;
    use crate::publisher::ttrpc::r#async::TtrpcContext;

    struct FakeServer {
        tx: Sender<i32>,
    }

    #[async_trait]
    impl Events for FakeServer {
        async fn forward(&self, _ctx: &TtrpcContext, req: ForwardRequest) -> ttrpc::Result<Empty> {
            let env = req.envelope();
            if env.topic() == "/tasks/oom" {
                self.tx.send(0).await.unwrap();
            } else {
                self.tx.send(-1).await.unwrap();
            }
            Ok(Empty::default())
        }
    }

    #[tokio::test]
    async fn test_connect() {
        let tmpdir = tempfile::tempdir().unwrap();
        let path = format!("{}/socket", tmpdir.as_ref().to_str().unwrap());
        let path1 = path.clone();

        assert!(RemotePublisher::connect("a".repeat(16384)).await.is_err());
        assert!(RemotePublisher::connect(&path).await.is_err());

        let (tx, mut rx) = channel(1);
        let server = FakeServer { tx };
        let barrier = Arc::new(Barrier::new(2));
        let barrier2 = barrier.clone();
        let server_thread = tokio::spawn(async move {
            let listener = UnixListener::bind(&path1).unwrap();
            let listener = Listener::try_from(listener).unwrap();
            let service = create_events(Arc::new(server));
            let mut server = Server::new()
                .add_listener(listener)
                .register_service(service);
            server.start().await.unwrap();
            barrier2.wait().await;

            barrier2.wait().await;
            server.shutdown().await.unwrap();
        });

        barrier.wait().await;
        let client = RemotePublisher::new(&path).await.unwrap();
        let mut msg = TaskOOM::new();
        msg.set_container_id("test".to_string());
        client
            .publish(Context::default(), "/tasks/oom", "ns1", Box::new(msg))
            .await
            .unwrap();
        match rx.recv().await {
            Some(0) => {}
            _ => {
                panic!("the received event is not same as published")
            }
        }
        barrier.wait().await;
        server_thread.await.unwrap();
    }
}
