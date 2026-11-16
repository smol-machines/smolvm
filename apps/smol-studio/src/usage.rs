//! Visible-only resource sampling through the selected public CLI.
use crate::{
    model::Operation,
    runtime::{Payload, Runtime, Worker},
};
use serde::Deserialize;
use std::{
    collections::VecDeque,
    sync::Arc,
    time::{Duration, Instant},
};

pub const INTERVAL: Duration = Duration::from_secs(5);
pub const HISTORY_WINDOW: Duration = Duration::from_secs(300);
const HISTORY_LIMIT: usize = 60;

#[derive(Clone, Debug, Deserialize)]
pub struct Memory {
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Sample {
    pub name: String,
    pub cpus: u16,
    pub cpu_percent: Option<f64>,
    pub memory: Option<Memory>,
}

impl Sample {
    pub fn parse(text: &str, expected: &str) -> Result<Self, String> {
        let sample: Self =
            serde_json::from_str(text).map_err(|e| format!("Cannot read resource usage: {e}"))?;
        if sample.name != expected || sample.cpus == 0 {
            return Err("The runtime returned usage for an invalid or different machine.".into());
        }
        if sample
            .cpu_percent
            .is_some_and(|v| !v.is_finite() || v < 0.0)
            || sample.memory.as_ref().is_some_and(|m| {
                m.total_bytes == 0
                    || m.used_bytes > m.total_bytes
                    || m.available_bytes > m.total_bytes
            })
        {
            return Err("The runtime returned invalid resource measurements.".into());
        }
        Ok(sample)
    }
}

#[derive(Clone, PartialEq)]
pub struct Target {
    pub runtime: Runtime,
    pub name: String,
    pub pid: Option<u32>,
}

pub struct Point {
    pub at: Instant,
    pub sample: Sample,
}

pub struct Usage {
    wake: Arc<dyn Fn() + Send + Sync>,
    target: Option<Target>,
    worker: Option<Worker>,
    pending: bool,
    next: Option<Instant>,
    pub history: VecDeque<Point>,
    pub error: Option<String>,
    pub active: bool,
}

impl Usage {
    pub fn new(wake: impl Fn() + Send + Sync + 'static) -> Self {
        Self {
            wake: Arc::new(wake),
            target: None,
            worker: None,
            pending: false,
            next: None,
            history: VecDeque::new(),
            error: None,
            active: false,
        }
    }

    pub fn pending(&self) -> bool {
        self.pending
    }

    pub fn update(&mut self, target: Option<Target>, active: bool, now: Instant) {
        if self.target != target {
            self.worker = None;
            self.pending = false;
            self.next = None;
            self.history.clear();
            self.error = None;
            self.target = target;
        }
        self.active = active && self.target.is_some();
        if !self.active {
            // Worker cancellation kills/reaps only its read-only CLI process.
            self.worker = None;
            self.pending = false;
            self.next = None;
            return;
        }
        let target = self.target.as_ref().unwrap();
        let worker = self.worker.get_or_insert_with(|| {
            let wake = self.wake.clone();
            Worker::new(move || wake())
        });
        if let Ok(done) = worker.responses.try_recv() {
            self.pending = false;
            self.next = Some(now + INTERVAL);
            let result = match done.result {
                Ok(Payload::Output { name, text }) if name == target.name => {
                    Sample::parse(&text, &name)
                }
                Ok(_) => Err("The runtime returned an unexpected usage response.".into()),
                Err(error) => Err(error),
            };
            match result {
                Ok(sample) => {
                    self.error = None;
                    self.history.push_back(Point { at: now, sample });
                    while self.history.len() > HISTORY_LIMIT
                        || self
                            .history
                            .front()
                            .is_some_and(|p| now.saturating_duration_since(p.at) > HISTORY_WINDOW)
                    {
                        self.history.pop_front();
                    }
                }
                Err(error) => self.error = Some(error),
            }
        }
        if !self.pending && self.next.is_none_or(|next| now >= next) {
            match worker.submit(
                target.runtime.clone(),
                Operation::Stats(target.name.clone()),
            ) {
                Ok(()) => self.pending = true,
                Err(error) => {
                    self.error = Some(error);
                    self.next = Some(now + INTERVAL);
                }
            }
        }
    }

    pub fn repaint_after(&self, now: Instant) -> Option<Duration> {
        (self.active && !self.pending).then(|| {
            self.next
                .map(|next| next.saturating_duration_since(now))
                .unwrap_or(Duration::ZERO)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_is_not_zero_and_invalid_or_mismatched_samples_are_rejected() {
        let unknown = Sample::parse(
            r#"{"name":"vm","cpus":2,"cpu_percent":null,"memory":null}"#,
            "vm",
        )
        .unwrap();
        assert!(unknown.cpu_percent.is_none() && unknown.memory.is_none());
        let measured = Sample::parse(r#"{"name":"vm","cpus":2,"cpu_percent":150.0,"memory":{"total_bytes":100,"used_bytes":25,"available_bytes":75}}"#, "vm").unwrap();
        assert_eq!(measured.cpu_percent, Some(150.0));
        for text in [
            r#"{"name":"other","cpus":2}"#,
            r#"{"name":"vm","cpus":0}"#,
            r#"{"name":"vm","cpus":2,"cpu_percent":-1}"#,
            r#"{"name":"vm","cpus":2,"memory":{"total_bytes":0,"used_bytes":0,"available_bytes":0}}"#,
            r#"{"name":"vm","cpus":2,"memory":{"total_bytes":100,"used_bytes":101,"available_bytes":0}}"#,
        ] {
            assert!(Sample::parse(text, "vm").is_err());
        }
    }

    #[cfg(unix)]
    fn fixture() -> (tempfile::TempDir, Target) {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("chosen cli");
        std::fs::write(
            &executable,
            r#"#!/bin/sh
echo $$ > "$SMOLVM_DATA_DIR/pid"
printf '[%s]\n' "$@" > "$SMOLVM_DATA_DIR/args"
if [ -e "$SMOLVM_DATA_DIR/hold" ]; then
    touch "$SMOLVM_DATA_DIR/started"
    while [ -e "$SMOLVM_DATA_DIR/hold" ]; do sleep 0.01; done
fi
cat "$SMOLVM_DATA_DIR/sample"
"#,
        )
        .unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(
            dir.path().join("sample"),
            r#"{"name":"vm","cpus":2,"cpu_percent":0,"memory":null}"#,
        )
        .unwrap();
        let target = Target {
            runtime: Runtime {
                executable,
                state_dir: Some(dir.path().to_path_buf()),
            },
            name: "vm".into(),
            pid: Some(42),
        };
        (dir, target)
    }

    #[cfg(unix)]
    fn until(mut check: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !check() {
            assert!(Instant::now() < deadline, "usage worker did not complete");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[cfg(unix)]
    #[test]
    fn sampling_waits_between_reads_preserves_failure_context_and_bounds_history() {
        let (dir, target) = fixture();
        let mut usage = Usage::new(|| {});
        let mut now = Instant::now();
        for _ in 0..70 {
            usage.update(Some(target.clone()), true, now);
            until(|| {
                usage.update(Some(target.clone()), true, now);
                !usage.pending
            });
            assert_eq!(usage.repaint_after(now), Some(INTERVAL));
            assert!(usage.history.len() <= HISTORY_LIMIT);
            assert!(now.duration_since(usage.history.front().unwrap().at) <= HISTORY_WINDOW);
            now += INTERVAL + Duration::from_millis(1);
        }
        assert!(usage.history.len() > 1);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("args")).unwrap(),
            "[_engine]\n[machine]\n[stats]\n[--name]\n[vm]\n[--json]\n"
        );
        let last = usage.history.back().unwrap().at;
        std::fs::write(dir.path().join("sample"), "not-json").unwrap();
        usage.update(Some(target.clone()), true, now);
        until(|| {
            usage.update(Some(target.clone()), true, now);
            !usage.pending
        });
        assert!(usage.error.is_some());
        assert_eq!(usage.history.back().unwrap().at, last);
        usage.update(Some(target), false, now);
        assert!(!usage.active && usage.worker.is_none() && !usage.pending());
        assert!(usage.repaint_after(now).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn hiding_reaps_inflight_reader_and_new_process_identity_drops_old_samples() {
        let (dir, target) = fixture();
        let mut usage = Usage::new(|| {});
        let now = Instant::now();
        usage.update(Some(target.clone()), true, now);
        until(|| {
            usage.update(Some(target.clone()), true, now);
            !usage.history.is_empty()
        });
        std::fs::write(dir.path().join("hold"), "").unwrap();
        usage.update(Some(target.clone()), true, now + INTERVAL);
        until(|| dir.path().join("started").exists());
        let pid = std::fs::read_to_string(dir.path().join("pid"))
            .unwrap()
            .trim()
            .parse::<i32>()
            .unwrap();
        usage.update(Some(target.clone()), false, now + INTERVAL);
        assert_eq!(
            unsafe { libc::kill(pid, 0) },
            -1,
            "hidden observer must reap its own CLI"
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
        assert_eq!(usage.history.len(), 1);
        let changed = Target {
            pid: Some(43),
            ..target
        };
        usage.update(Some(changed), false, now + INTERVAL);
        assert!(usage.history.is_empty());
        assert!(!usage.pending());
    }
}
