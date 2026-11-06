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
use std::fmt;

#[cfg(feature = "async")]
pub use crate::asynchronous::monitor::*;
#[cfg(not(feature = "async"))]
pub use crate::synchronous::monitor::*;

#[derive(Clone, Eq, Hash, PartialEq)]
pub enum Topic {
    Pid,
    Exec,
    All,
}

#[derive(Debug)]
pub struct ExitEvent {
    // what kind of a thing exit
    pub subject: Subject,
    pub exit_code: i32,
}

impl fmt::Display for ExitEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.subject {
            Subject::Pid(pid) => {
                write!(f, "PID {} exit with code {}", pid, self.exit_code)
            }
            Subject::Exec(cid, eid) => {
                write!(
                    f,
                    "EXEC process {} inside {} exit with code {}",
                    eid, cid, self.exit_code
                )
            }
        }
    }
}

#[derive(Clone, Debug)]
pub enum Subject {
    // process pid
    Pid(i32),
    // exec with containerd id and exec id for vm container,
    // if exec is empty, then the event is for the container
    Exec(String, String),
}
