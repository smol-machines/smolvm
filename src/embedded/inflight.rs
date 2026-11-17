//! Fences a machine's lifecycle calls against work already running on it.
//!
//! Commands and file transfers run on their own agent connections, so a stop
//! or delete used to land in the middle of one and the caller saw only a
//! dropped connection. Each such operation now holds an [`Operation`] for its
//! duration. A stop or delete raises a [`Fence`] first: new operations are
//! refused with a clear "machine is stopping" error, running ones may be given
//! time to finish, and one the stop cuts off reports [`Error::Interrupted`]
//! instead of whatever the broken connection said.

use crate::error::{Error, Result};
use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

#[derive(Default)]
struct State {
    running: usize,
    /// What the raised fence is doing to the machine ("stopped", "deleted").
    stopping: Option<&'static str>,
    /// Bumped by every fence, so an operation can tell one rose while it ran.
    generation: u64,
}

#[derive(Default)]
struct Machine {
    state: Mutex<State>,
    idle: Condvar,
}

impl Machine {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// In-flight operations per machine name.
#[derive(Default)]
pub(crate) struct Inflight {
    machines: Mutex<HashMap<String, Arc<Machine>>>,
}

impl Inflight {
    fn machine(&self, name: &str) -> Arc<Machine> {
        let mut machines = self.machines.lock().unwrap_or_else(|e| e.into_inner());
        Arc::clone(machines.entry(name.to_string()).or_default())
    }

    /// Start `operation` on `name`, or refuse it while the machine is being
    /// stopped or deleted.
    pub(crate) fn begin(&self, name: &str, operation: &str) -> Result<Operation> {
        let machine = self.machine(name);
        let generation = {
            let mut state = machine.lock();
            if let Some(by) = state.stopping {
                return Err(Error::agent_conflict(
                    operation.to_string(),
                    format!("machine '{name}' is being {by}"),
                ));
            }
            state.running += 1;
            state.generation
        };
        Ok(Operation {
            machine,
            name: name.to_string(),
            operation: operation.to_string(),
            generation,
        })
    }

    /// Raise the fence for a stop (`by` = "stopped") or delete ("deleted"),
    /// then wait up to `drain` for running operations to finish. The fence
    /// stays up until the returned guard is dropped.
    pub(crate) fn fence(&self, name: &str, by: &'static str, drain: Option<Duration>) -> Fence {
        let machine = self.machine(name);
        {
            let mut state = machine.lock();
            state.stopping = Some(by);
            state.generation += 1;
            if let Some(drain) = drain {
                let deadline = Instant::now() + drain;
                while state.running > 0 {
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        break;
                    }
                    state = machine
                        .idle
                        .wait_timeout(state, left)
                        .unwrap_or_else(|e| e.into_inner())
                        .0;
                }
            }
        }
        Fence { machine }
    }
}

/// One running command or file transfer.
pub(crate) struct Operation {
    machine: Arc<Machine>,
    name: String,
    operation: String,
    generation: u64,
}

impl Operation {
    /// The operation's result, with a failure caused by a stop or delete that
    /// ran meanwhile reported as such.
    pub(crate) fn finish<T>(self, result: Result<T>) -> Result<T> {
        let Err(error) = result else {
            return result;
        };
        let cut_off_by = {
            let state = self.machine.lock();
            (state.generation != self.generation).then(|| state.stopping.unwrap_or("stopped"))
        };
        match cut_off_by {
            Some(by) => Err(Error::Interrupted {
                name: self.name.clone(),
                operation: self.operation.clone(),
                by: by.to_string(),
                reason: error.to_string(),
            }),
            None => Err(error),
        }
    }
}

impl Drop for Operation {
    fn drop(&mut self) {
        let mut state = self.machine.lock();
        state.running = state.running.saturating_sub(1);
        if state.running == 0 {
            self.machine.idle.notify_all();
        }
    }
}

/// A raised fence; dropping it lets operations start again.
pub(crate) struct Fence {
    machine: Arc<Machine>,
}

impl Drop for Fence {
    fn drop(&mut self) {
        self.machine.lock().stopping = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn broken() -> Result<()> {
        Err(Error::agent("exec", "connection closed"))
    }

    #[test]
    fn an_operation_cut_off_by_a_stop_reports_the_stop() {
        let inflight = Inflight::default();
        let op = inflight.begin("m", "exec").unwrap();
        let fence = inflight.fence("m", "stopped", None);
        let err = op.finish(broken()).unwrap_err();
        assert!(
            matches!(&err, Error::Interrupted { by, .. } if by == "stopped"),
            "{err}"
        );
        assert!(err.to_string().contains("machine 'm' was stopped"), "{err}");
        drop(fence);
    }

    #[test]
    fn a_failure_without_a_stop_is_reported_unchanged() {
        let inflight = Inflight::default();
        let op = inflight.begin("m", "exec").unwrap();
        let err = op.finish(broken()).unwrap_err();
        assert!(matches!(err, Error::Agent { .. }), "{err}");
    }

    #[test]
    fn success_is_success_even_when_a_stop_rose_meanwhile() {
        let inflight = Inflight::default();
        let op = inflight.begin("m", "exec").unwrap();
        let _fence = inflight.fence("m", "deleted", None);
        assert_eq!(op.finish(Ok(7)).unwrap(), 7);
    }

    #[test]
    fn new_operations_are_refused_until_the_fence_drops() {
        let inflight = Inflight::default();
        let fence = inflight.fence("m", "deleted", None);
        let err = inflight.begin("m", "write file").err().unwrap();
        assert!(
            err.to_string().contains("machine 'm' is being deleted"),
            "{err}"
        );
        assert!(
            inflight.begin("other", "exec").is_ok(),
            "other machines are unaffected"
        );
        drop(fence);
        assert!(inflight.begin("m", "exec").is_ok());
    }

    #[test]
    fn a_drain_waits_for_running_operations_then_gives_up() {
        let inflight = Arc::new(Inflight::default());
        let op = inflight.begin("m", "exec").unwrap();
        let finisher = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            drop(op);
        });
        let started = Instant::now();
        drop(inflight.fence("m", "stopped", Some(Duration::from_secs(5))));
        let waited = started.elapsed();
        assert!(
            waited >= Duration::from_millis(140) && waited < Duration::from_secs(4),
            "{waited:?}"
        );
        finisher.join().unwrap();

        let _stuck = inflight.begin("m", "exec").unwrap();
        let started = Instant::now();
        drop(inflight.fence("m", "stopped", Some(Duration::from_millis(100))));
        let waited = started.elapsed();
        assert!(
            waited >= Duration::from_millis(90) && waited < Duration::from_secs(2),
            "{waited:?}"
        );
    }
}
