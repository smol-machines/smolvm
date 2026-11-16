//! A bounded live transcript for a command owned by the action worker.
use crate::log_stream::{LogStream, Status as LogStatus};
use std::{
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Clone, Debug, PartialEq)]
pub enum Status {
    Running,
    Succeeded,
    Failed,
}

#[derive(Clone)]
pub struct Snapshot {
    pub revision: u64,
    pub id: u64,
    pub title: String,
    pub text: String,
    pub discarded: bool,
    pub status: Status,
}

#[derive(Clone)]
pub struct Progress {
    state: Arc<Mutex<Snapshot>>,
    wake: Arc<dyn Fn() + Send + Sync>,
}
impl Progress {
    pub fn new(wake: impl Fn() + Send + Sync + 'static) -> Self {
        Self {
            state: Arc::new(Mutex::new(Snapshot {
                revision: 0,
                id: 0,
                title: String::new(),
                text: String::new(),
                discarded: false,
                status: Status::Succeeded,
            })),
            wake: Arc::new(wake),
        }
    }
    pub fn snapshot_after(&self, revision: u64) -> Option<Snapshot> {
        let state = self.state.lock().unwrap();
        (state.revision != revision).then(|| state.clone())
    }
    pub(crate) fn begin(&self, title: String) {
        let mut state = self.state.lock().unwrap();
        let revision = state.revision.wrapping_add(1);
        let id = state.id.wrapping_add(1);
        *state = Snapshot {
            revision,
            id,
            title,
            text: String::new(),
            discarded: false,
            status: Status::Running,
        };
        drop(state);
        (self.wake)();
    }
    pub(crate) fn finish(&self, success: bool) {
        let mut state = self.state.lock().unwrap();
        state.status = if success {
            Status::Succeeded
        } else {
            Status::Failed
        };
        state.revision = state.revision.wrapping_add(1);
        drop(state);
        (self.wake)();
    }
    pub(crate) fn capture(
        &self,
        command: Command,
        timeout: Duration,
        shutdown: &AtomicBool,
    ) -> Result<(), String> {
        // This reader belongs to the command, not to the visible output panel.
        // Hiding the panel never interrupts a build or image pull.
        let stream = LogStream::spawn(command, || {})?;
        let started = Instant::now();
        let mut revision = 0;
        loop {
            if let Some(snapshot) = stream.snapshot_after(revision) {
                revision = snapshot.revision;
                let mut state = self.state.lock().unwrap();
                state.text = snapshot.text;
                state.discarded = snapshot.discarded;
                state.revision = state.revision.wrapping_add(1);
                let status = snapshot.status;
                let failure = match &status {
                    LogStatus::Finished(code) if *code != 0 => {
                        let tail: String = state
                            .text
                            .chars()
                            .rev()
                            .take(4096)
                            .collect::<Vec<_>>()
                            .into_iter()
                            .rev()
                            .collect();
                        Some(format!("Command exited with code {code}.\n{}", tail.trim()))
                    }
                    LogStatus::Failed(error) => Some(error.clone()),
                    _ => None,
                };
                drop(state);
                (self.wake)();
                if let Some(error) = failure {
                    return Err(error);
                }
                if matches!(status, LogStatus::Finished(0)) {
                    return Ok(());
                }
            }
            if shutdown.load(Ordering::Relaxed) {
                return Err("Studio closed; the command was interrupted. Check project state before retrying.".into());
            }
            if started.elapsed() >= timeout {
                return Err("The command timed out and may have partially completed. Refresh project state before retrying.".into());
            }
            thread::sleep(Duration::from_millis(50));
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    fn shell(script: &str, directory: &std::path::Path) -> Command {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", script]).current_dir(directory);
        cmd
    }
    fn until(mut check: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !check() {
            assert!(Instant::now() < deadline, "condition did not complete");
            thread::sleep(Duration::from_millis(10));
        }
    }
    #[test]
    fn output_is_visible_before_exit_and_retention_does_not_interrupt_verbose_commands() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("hold"), "").unwrap();
        let p = Progress::new(|| {});
        p.begin("Build fixture".into());
        let report = p.clone();
        let cmd = shell(
            "printf 'early stdout\\n'; printf 'early stderr\\n' >&2; while test -f hold; do sleep 0.01; done; i=0; while test $i -lt 9000; do printf 'verbose build line abcdefghijklmnopqrstuvwxyz\\n' >&2; i=$((i+1)); done; printf 'last line\\n'",
            dir.path(),
        );
        let worker = thread::spawn(move || {
            let result = report.capture(cmd, Duration::from_secs(10), &AtomicBool::new(false));
            report.finish(result.is_ok());
            result
        });
        until(|| {
            p.snapshot_after(0)
                .is_some_and(|s| s.text.contains("early stdout") && s.text.contains("early stderr"))
        });
        assert_eq!(p.snapshot_after(0).unwrap().status, Status::Running);
        std::fs::remove_file(dir.path().join("hold")).unwrap();
        worker.join().unwrap().unwrap();
        let snap = p.snapshot_after(0).unwrap();
        assert_eq!(snap.status, Status::Succeeded);
        assert!(snap.discarded);
        assert!(snap.text.len() <= 256 * 1024 && snap.text.lines().count() <= 2000);
        assert!(snap.text.contains("last line"));
        assert!(p.snapshot_after(snap.revision).is_none());
        p.begin("Next command".into());
        let next = p.snapshot_after(snap.revision).unwrap();
        assert_ne!(next.id, snap.id);
        assert!(next.text.is_empty());
        assert!(!next.discarded);
    }
    #[test]
    fn failure_keeps_last_diagnostics_and_timeout_reaps_owned_process() {
        let dir = tempfile::tempdir().unwrap();
        let p = Progress::new(|| {});
        p.begin("Failing fixture".into());
        let error = p
            .capture(
                shell("printf 'failure detail\\n' >&2; exit 7", dir.path()),
                Duration::from_secs(5),
                &AtomicBool::new(false),
            )
            .unwrap_err();
        p.finish(false);
        assert!(error.contains("code 7") && error.contains("failure detail"));
        assert_eq!(p.snapshot_after(0).unwrap().status, Status::Failed);
        assert!(p.snapshot_after(0).unwrap().text.contains("failure detail"));
        let error = p
            .capture(
                shell("echo $$ > pid; exec sleep 30", dir.path()),
                Duration::from_millis(200),
                &AtomicBool::new(false),
            )
            .unwrap_err();
        assert!(error.contains("timed out"));
        let pid: i32 = std::fs::read_to_string(dir.path().join("pid"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        until(|| unsafe { libc::kill(pid, 0) } == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH));
    }
}
