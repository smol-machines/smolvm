//! A visible workspace owns one event subscription, with coalesced refreshes.
use crate::log_stream::{LogStream, Status};
use std::{
    process::Command,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const COALESCE: Duration = Duration::from_millis(250);
const MIN_REFRESH: Duration = Duration::from_secs(1);

#[derive(Default)]
struct Changes {
    due: Option<Instant>,
    last: Option<Instant>,
}
impl Changes {
    fn mark(&mut self, now: Instant) {
        if self.due.is_none() {
            self.due =
                Some((now + COALESCE).max(self.last.map(|last| last + MIN_REFRESH).unwrap_or(now)));
        }
    }
    fn take(&mut self, now: Instant, busy: bool) -> bool {
        if !busy && self.due.is_some_and(|due| now >= due) {
            self.due = None;
            self.last = Some(now);
            true
        } else {
            false
        }
    }
}

#[derive(Default)]
pub struct EventWatch {
    stream: Option<LogStream>,
    revision: u64,
    visible: bool,
    changes: Changes,
    retry_at: Option<Instant>,
    failures: u32,
    disconnected: bool,
}

pub struct Poll {
    pub refresh: bool,
    pub wake_after: Option<Duration>,
}

fn event_command() -> Command {
    let mut command = Command::new(crate::runtime::find_tool(if cfg!(windows) {
        "docker.exe"
    } else {
        "docker"
    }));
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .to_string();
    // Inclusive second closes the gap between subscribing and fetching inventory.
    // A reconnect also refreshes inventory to recover changes missed while hidden.
    command.args([
        "--context",
        "smol",
        "events",
        "--since",
        &since,
        "--format",
        "{{.Type}}",
    ]);
    for kind in ["container", "image", "volume", "network"] {
        command.args(["--filter", &format!("type={kind}")]);
    }
    // Exec/attach/log activity does not alter inventory and must not refresh it.
    for event in [
        "create",
        "start",
        "stop",
        "die",
        "destroy",
        "rename",
        "pause",
        "unpause",
        "restart",
        "update",
        "health_status",
        "pull",
        "push",
        "load",
        "import",
        "commit",
        "tag",
        "untag",
        "delete",
        "connect",
        "disconnect",
        "prune",
    ] {
        command.args(["--filter", &format!("event={event}")]);
    }
    command
        .env_remove("DOCKER_HOST")
        .env_remove("DOCKER_CONTEXT")
        .env("NO_COLOR", "1");
    command
}

impl EventWatch {
    pub fn disconnected(&self) -> bool {
        self.disconnected
    }

    pub fn poll(
        &mut self,
        now: Instant,
        visible: bool,
        busy: bool,
        wake: impl Fn() + Send + Sync + 'static,
    ) -> Poll {
        if !visible {
            self.stream = None;
            self.visible = false;
            self.changes = Changes::default();
            self.retry_at = None;
            self.failures = 0;
            self.disconnected = false;
            return Poll {
                refresh: false,
                wake_after: None,
            };
        }
        if !self.visible {
            self.visible = true;
            self.changes.mark(now);
        }
        if self.stream.is_none() && self.retry_at.is_none_or(|retry| now >= retry) {
            self.retry_at = None;
            match LogStream::spawn(event_command(), wake) {
                Ok(stream) => {
                    self.stream = Some(stream);
                    self.revision = 0;
                    self.changes.mark(now);
                }
                Err(_) => self.failed(now),
            }
        }
        if let Some(stream) = &self.stream
            && let Some(activity) = stream.activity_after(self.revision)
        {
            self.revision = activity.revision;
            if activity.has_output {
                self.changes.mark(now);
            }
            if activity.status != Status::Following {
                self.failed(now);
            } else if activity.has_output {
                self.failures = 0;
                self.disconnected = false;
            }
        }
        let refresh = self.changes.take(now, busy);
        let due = self
            .changes
            .due
            .filter(|_| !busy)
            .into_iter()
            .chain(self.retry_at)
            .min();
        Poll {
            refresh,
            wake_after: due.map(|due| due.saturating_duration_since(now)),
        }
    }
    fn failed(&mut self, now: Instant) {
        self.stream = None;
        self.disconnected = true;
        self.failures = self.failures.saturating_add(1);
        let seconds = (1u64 << self.failures.min(5)).min(30);
        self.retry_at = Some(now + Duration::from_secs(seconds));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bursts_coalesce_without_starvation_and_wait_for_operations() {
        let mut changes = Changes::default();
        let now = Instant::now();
        changes.mark(now);
        changes.mark(now + Duration::from_millis(200));
        assert!(!changes.take(now + Duration::from_millis(249), false));
        assert!(!changes.take(now + COALESCE, true));
        assert!(changes.take(now + COALESCE, false));
        changes.mark(now + Duration::from_millis(300));
        assert!(!changes.take(now + Duration::from_secs(1), false));
        assert!(changes.take(now + COALESCE + MIN_REFRESH, false));
        assert!(!changes.take(now + Duration::from_secs(10), false));
    }
    #[test]
    fn event_subscription_is_explicit_and_excludes_exec_noise() {
        let command = event_command();
        let args: Vec<_> = command.get_args().map(|s| s.to_str().unwrap()).collect();
        assert_eq!(&args[..3], ["--context", "smol", "events"]);
        assert!(args.contains(&"event=die"));
        assert!(args.contains(&"event=health_status"));
        assert!(
            !args
                .iter()
                .any(|s| s.starts_with("event=exec") || *s == "event=attach")
        );
        assert!(
            command
                .get_envs()
                .any(|(k, v)| k == "DOCKER_HOST" && v.is_none())
        );
        assert!(
            command
                .get_envs()
                .any(|(k, v)| k == "DOCKER_CONTEXT" && v.is_none())
        );
    }
    #[test]
    fn failures_back_off_and_hidden_workspaces_have_no_timers() {
        let mut watch = EventWatch::default();
        let now = Instant::now();
        for delay in [2, 4, 8, 16, 30, 30] {
            watch.failed(now);
            assert_eq!(watch.retry_at, Some(now + Duration::from_secs(delay)));
        }
        let poll = watch.poll(now, false, false, || {});
        assert!(!poll.refresh && poll.wake_after.is_none());
        assert!(watch.stream.is_none());
        assert!(!watch.disconnected());
    }
}
