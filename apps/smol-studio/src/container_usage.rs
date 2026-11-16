//! Read-only Docker measurements, sampled only for the active container view.
use crate::{
    docker::{Action, DockerWorker, Output},
    runtime::Runtime,
};
use serde_json::Value;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

pub const INTERVAL: Duration = Duration::from_secs(5);

#[derive(Clone, PartialEq)]
pub struct Target {
    pub runtime: Runtime,
    pub id: String,
    pub started_at: String,
}

pub struct Sample {
    pub cpu: String,
    pub memory: String,
}
impl Sample {
    pub fn parse(value: &Value, id: &str) -> Result<Self, String> {
        let actual = value["ID"]
            .as_str()
            .ok_or("Usage response has no container ID.")?;
        if actual.len() < 12 || !id.starts_with(actual) {
            return Err("Usage response belongs to a different container.".into());
        }
        let field = |key: &str| {
            value[key]
                .as_str()
                .filter(|s| !s.is_empty() && s.len() <= 128)
                .map(str::to_owned)
                .ok_or_else(|| format!("Usage response has no valid {key} measurement."))
        };
        Ok(Self {
            cpu: field("CPUPerc")?,
            memory: field("MemUsage")?,
        })
    }
}

pub struct Usage {
    wake: Arc<dyn Fn() + Send + Sync>,
    target: Option<Target>,
    worker: Option<DockerWorker>,
    pending: bool,
    next: Option<Instant>,
    pub sample: Option<(Instant, Sample)>,
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
            sample: None,
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
            self.sample = None;
            self.error = None;
            self.target = target;
        }
        self.active = active && self.target.is_some();
        if !self.active {
            // Drop cancels and reaps this reader without touching the workload.
            self.worker = None;
            self.pending = false;
            self.next = None;
            return;
        }
        let target = self.target.as_ref().unwrap();
        let worker = self.worker.get_or_insert_with(|| {
            let wake = self.wake.clone();
            DockerWorker::new(move || wake())
        });
        if let Ok(done) = worker.events.try_recv() {
            self.pending = false;
            self.next = Some(now + INTERVAL);
            let result = match done.result {
                Ok(Output::Stats { id, value }) if id == target.id => Sample::parse(&value, &id),
                Ok(_) => Err("Unexpected resource usage response.".into()),
                Err(error) => Err(error),
            };
            match result {
                Ok(sample) => {
                    self.sample = Some((now, sample));
                    self.error = None;
                }
                Err(error) => self.error = Some(error),
            }
        }
        if !self.pending && self.next.is_none_or(|next| now >= next) {
            match worker.submit(target.runtime.clone(), Action::Stats(target.id.clone())) {
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
                .map(|n| n.saturating_duration_since(now))
                .unwrap_or_default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_and_wrong_container_measurements_are_not_presented_as_zero() {
        let id = "a".repeat(64);
        let mut value =
            serde_json::json!({"ID": &id[..12], "CPUPerc":"0.00%", "MemUsage":"1MiB / 1GiB"});
        assert_eq!(Sample::parse(&value, &id).unwrap().cpu, "0.00%");
        assert!(Sample::parse(&value, &"b".repeat(64)).is_err());
        value["ID"] = "".into();
        assert!(Sample::parse(&value, &id).is_err());
        value["ID"] = id.clone().into();
        value["CPUPerc"] = Value::Null;
        assert!(Sample::parse(&value, &id).is_err());
    }

    #[test]
    #[ignore = "requires an explicitly owned running container in an isolated smol context"]
    fn live_sampling_pauses_resumes_and_clears_previous_container() {
        let id = std::env::var("SMOL_STUDIO_USAGE_CONTAINER").expect("owned container ID");
        let target = Target {
            runtime: Runtime::discover(),
            id,
            started_at: "first".into(),
        };
        let mut usage = Usage::new(|| {});
        let mut now = Instant::now();
        usage.update(Some(target.clone()), false, now);
        assert!(usage.worker.is_none());
        usage.update(Some(target.clone()), true, now);
        let deadline = Instant::now() + Duration::from_secs(30);
        while usage.pending() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
            now = Instant::now();
            usage.update(Some(target.clone()), true, now);
        }
        assert!(usage.error.is_none(), "{:?}", usage.error);
        assert!(usage.sample.is_some());
        assert_eq!(usage.repaint_after(now), Some(INTERVAL));
        usage.update(Some(target.clone()), true, now + Duration::from_secs(1));
        assert!(!usage.pending());
        usage.update(Some(target.clone()), false, now);
        assert!(usage.worker.is_none());
        assert!(usage.sample.is_some());
        assert_eq!(usage.repaint_after(now), None);
        usage.update(Some(target.clone()), true, now);
        assert!(usage.pending());
        usage.update(
            Some(Target {
                started_at: "restarted".into(),
                ..target
            }),
            false,
            now,
        );
        assert!(usage.sample.is_none() && usage.worker.is_none() && !usage.pending());
        let missing = Target {
            runtime: Runtime::discover(),
            id: "0".repeat(64),
            started_at: String::new(),
        };
        usage.update(Some(missing.clone()), true, now);
        let deadline = Instant::now() + Duration::from_secs(30);
        while usage.pending() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
            now = Instant::now();
            usage.update(Some(missing.clone()), true, now);
        }
        assert!(usage.error.is_some() && usage.sample.is_none());
        assert_eq!(usage.repaint_after(now), Some(INTERVAL));
        usage.update(Some(missing), true, now + Duration::from_secs(1));
        assert!(
            !usage.pending(),
            "failures must not cause a tight retry loop"
        );
        usage.update(None, false, now);
        assert!(usage.target.is_none() && usage.worker.is_none());
    }
}
