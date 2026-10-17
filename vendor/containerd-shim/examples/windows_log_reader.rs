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
#[cfg(windows)]
use std::error::Error;

#[cfg(windows)]
fn main() -> Result<(), Box<dyn Error>> {
    use std::{
        env,
        fs::OpenOptions,
        os::windows::{
            fs::OpenOptionsExt,
            io::{FromRawHandle, IntoRawHandle},
        },
        time::Duration,
    };

    use mio::{windows::NamedPipe, Events, Interest, Poll, Token};
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OVERLAPPED;

    let args: Vec<String> = env::args().collect();

    let address = args
        .get(1)
        .ok_or("First argument must be shims address to read logs (\\\\.\\pipe\\containerd-shim-{ns}-{id}-log) ")
        .unwrap();

    println!("Reading logs from: {}", &address);

    let mut opts = OpenOptions::new();
    opts.read(true)
        .write(true)
        .custom_flags(FILE_FLAG_OVERLAPPED);
    let file = opts.open(address).unwrap();
    let mut client = unsafe { NamedPipe::from_raw_handle(file.into_raw_handle()) };

    let mut stdio = std::io::stdout();
    let mut poll = Poll::new().unwrap();
    poll.registry()
        .register(&mut client, Token(1), Interest::READABLE)
        .unwrap();
    let mut events = Events::with_capacity(128);
    loop {
        poll.poll(&mut events, Some(Duration::from_millis(10)))
            .unwrap();
        match std::io::copy(&mut client, &mut stdio) {
            Ok(_) => break,
            Err(_) => continue,
        }
    }

    Ok(())
}

#[cfg(unix)]
fn main() {
    println!("This example is only for Windows");
}
