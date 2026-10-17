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
use std::env;

use containerd_shim::{publisher::RemotePublisher, Context};
use containerd_shim_protos::events::task::TaskOOM;

#[cfg(not(feature = "async"))]
fn main() {
    let args: Vec<String> = env::args().collect();

    // Must not start with unix://
    let address = args
        .get(1)
        .ok_or("First argument must be containerd's TTRPC address to publish events")
        .unwrap();

    println!("Connecting: {}", &address);

    let publisher = RemotePublisher::new(address).expect("Connect failed");

    let mut event = TaskOOM::new();
    event.set_container_id("123".into());

    let ctx = Context::default();

    println!("Sending event");

    publisher
        .publish(ctx, "/tasks/oom", "default", Box::new(event))
        .expect("Publish failed");

    println!("Done");
}

#[cfg(feature = "async")]
#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    // Must not start with unix://
    let address = args
        .get(1)
        .ok_or("First argument must be containerd's TTRPC address to publish events")
        .unwrap();

    println!("Connecting: {}", &address);

    let publisher = RemotePublisher::new(address).await.expect("Connect failed");

    let mut event = TaskOOM::new();
    event.set_container_id("123".into());

    let ctx = Context::default();

    println!("Sending event");

    publisher
        .publish(ctx, "/tasks/oom", "default", Box::new(event))
        .await
        .expect("Publish failed");

    println!("Done");
}
