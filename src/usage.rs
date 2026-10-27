//! Local usage journal: what people do with machines, recorded on their own disk.
//!
//! Every lifecycle transition that reaches the engine database (create, branch,
//! start, stop, pause, resume, resize, delete, checkpoint, restore) appends one
//! JSON line to `<data_local_dir>/smolvm/usage/events.jsonl`. The journal exists
//! so the shape of real use can be seen: how deep branch trees go, how many
//! children a source fans out to, how long machines live, which operations
//! follow which. It never records command lines, paths, image names, labels,
//! environment or output. Machine names appear only as a per-install hash.
//!
//! Recording is local and on by default, like shell history; `SMOLVM_USAGE=0`
//! or `[usage] record = false` in the settings file turns it off. Nothing
//! leaves the host unless sharing is turned on explicitly (`[usage] share =
//! true`, `smol usage share on`), in which case batches are posted to the
//! configured endpoint and an offset marks what has been sent.
//!
//! Every function here is best-effort: a journal failure never fails the
//! operation that triggered it.

use crate::config::VmRecord;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::sync::OnceLock;

/// Journal schema version carried on every event.
pub const SCHEMA_VERSION: u32 = 1;
/// Rotate the live journal past this size; one rotated file is kept.
const ROTATE_BYTES: u64 = 8 * 1024 * 1024;
/// Where shared batches go unless `[usage] endpoint` says otherwise.
pub const DEFAULT_SHARE_ENDPOINT: &str = "https://usage.smolmachines.com/v1/events";
/// Automatic sharing (from the CLI exit path) runs at most this often.
const AUTO_SHARE_INTERVAL_SECS: u64 = 3600;
/// Branch trees deeper than this are reported as this depth.
const MAX_DEPTH_WALK: usize = 64;

/// Settings for the journal, `[usage]` in the unified settings file.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct UsageSection {
    /// Record events locally. Default true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<bool>,
    /// Upload recorded events to `endpoint`. Default false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub share: Option<bool>,
    /// Where shared batches are posted. Default [`DEFAULT_SHARE_ENDPOINT`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

impl UsageSection {
    /// Whether events are appended to the local journal.
    pub fn record_enabled(&self) -> bool {
        self.record.unwrap_or(true)
    }
    /// Whether recorded events are uploaded.
    pub fn share_enabled(&self) -> bool {
        self.share.unwrap_or(false)
    }
    /// Where shared batches are posted.
    pub fn endpoint(&self) -> &str {
        self.endpoint
            .as_deref()
            .filter(|e| !e.trim().is_empty())
            .unwrap_or(DEFAULT_SHARE_ENDPOINT)
    }
}

/// One journal line.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Event {
    /// Schema version.
    pub v: u32,
    /// Unix time in milliseconds.
    pub ts: u64,
    /// Per-install random identifier (never derived from anything personal).
    pub install: String,
    /// Engine crate version.
    pub engine: String,
    /// Host operating system name.
    pub os: String,
    /// Host CPU architecture.
    pub arch: String,
    /// create, branch, start, resume, stop, pause, error, resize, delete, checkpoint, restore.
    pub event: String,
    /// sha256(install || machine name), first 16 hex chars.
    pub machine: String,
    /// Same hash of the branch source, for branch events and children generally.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    /// Number of branch hops from the root of this machine's tree.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub depth: Option<usize>,
    /// Machine started as a branch source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branchable: Option<bool>,
    /// Machine has CUDA remoting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cuda: Option<bool>,
    /// Machine was given a GPU.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu: Option<bool>,
    /// Machine has egress.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<bool>,
    /// Registry host of the image (never the repository or tag), or "none".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_host: Option<String>,
    /// Image reference carries a digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_pinned: Option<bool>,
    /// vCPUs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpus: Option<u8>,
    /// RAM ceiling in MiB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem_mib: Option<u32>,
    /// Number of host mounts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mounts: Option<usize>,
    /// Number of published ports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ports: Option<usize>,
    /// Seconds since the machine record was created (lifetime at this event).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub age_secs: Option<u64>,
    /// Record state before and after, for transitions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// Record state after the transition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Journal directory: `$SMOLVM_USAGE_DIR`, else `<data_local_dir>/smolvm/usage`.
pub fn journal_dir() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("SMOLVM_USAGE_DIR") {
        if dir.is_empty() {
            return None;
        }
        return Some(PathBuf::from(dir));
    }
    if cfg!(test) {
        // Unit tests elsewhere in the crate create records; keep them out of
        // the developer's real journal unless a test opts in with the env var.
        return None;
    }
    dirs::data_local_dir()
        .or_else(dirs::cache_dir)
        .map(|d| d.join("smolvm").join("usage"))
}

/// The live journal file.
pub fn journal_path() -> Option<PathBuf> {
    journal_dir().map(|d| d.join("events.jsonl"))
}

fn rotated_path() -> Option<PathBuf> {
    journal_dir().map(|d| d.join("events.1.jsonl"))
}

fn recording_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        if let Ok(v) = std::env::var("SMOLVM_USAGE") {
            let v = v.trim().to_ascii_lowercase();
            if matches!(v.as_str(), "0" | "off" | "false" | "no") {
                return false;
            }
            if matches!(v.as_str(), "1" | "on" | "true" | "yes") {
                return true;
            }
        }
        crate::settings::SmolSettings::load()
            .map(|s| s.usage.record_enabled())
            .unwrap_or(true)
    })
}

/// Random 128-bit identifier stored once per install. Uses the standard
/// library's randomly seeded hasher so no extra dependency is needed; the id
/// carries no information about the host.
pub fn install_id() -> String {
    static ID: OnceLock<String> = OnceLock::new();
    ID.get_or_init(|| {
        let Some(dir) = journal_dir() else {
            return "ephemeral".to_string();
        };
        let path = dir.join("install_id");
        if let Ok(existing) = std::fs::read_to_string(&path) {
            let trimmed = existing.trim();
            if trimmed.len() == 32 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
                return trimmed.to_string();
            }
        }
        let fresh = fresh_random_hex();
        if std::fs::create_dir_all(&dir).is_ok() {
            let _ = std::fs::write(&path, format!("{fresh}\n"));
        }
        fresh
    })
    .clone()
}

fn fresh_random_hex() -> String {
    use std::hash::{BuildHasher, Hasher};
    let mut out = String::with_capacity(32);
    for _ in 0..2 {
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u64(now_ms());
        hasher.write_u32(std::process::id());
        out.push_str(&format!("{:016x}", hasher.finish()));
    }
    out
}

/// Stable per-install token for a machine name.
pub fn machine_token(name: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(install_id().as_bytes());
    hasher.update(b"\0");
    hasher.update(name.as_bytes());
    let digest = hasher.finalize();
    digest.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

/// Registry host of an OCI reference and whether it is digest-pinned.
pub fn image_host(image: &str) -> (String, bool) {
    let pinned = image.contains('@');
    let without_digest = image.split('@').next().unwrap_or(image);
    let first = without_digest.split('/').next().unwrap_or(without_digest);
    let has_more = without_digest.contains('/');
    let host = if has_more && (first.contains('.') || first.contains(':') || first == "localhost") {
        first.to_string()
    } else if without_digest.starts_with("local:") {
        "local".to_string()
    } else {
        "docker.io".to_string()
    };
    (host, pinned)
}

/// Branch depth of `name`, walking parents through `parent_of`.
pub fn depth_of(name: &str, parent_of: &dyn Fn(&str) -> Option<String>) -> usize {
    let mut depth = 0;
    let mut current = name.to_string();
    let mut seen = std::collections::HashSet::new();
    while let Some(parent) = parent_of(&current) {
        if !seen.insert(current.clone()) || depth >= MAX_DEPTH_WALK {
            break;
        }
        depth += 1;
        current = parent;
    }
    depth
}

fn state_name(state: &crate::config::RecordState) -> String {
    format!("{state:?}").to_ascii_lowercase()
}

/// Build an event for `record` with the machine-shaped fields filled in.
pub fn event_for(kind: &str, name: &str, record: &VmRecord, depth: Option<usize>) -> Event {
    let (image_host, image_pinned) = match record.image.as_deref() {
        Some(image) => {
            let (host, pinned) = self::image_host(image);
            (Some(host), Some(pinned))
        }
        None => (Some("none".to_string()), None),
    };
    let now = now_ms();
    let age_secs = (now / 1000).checked_sub(record.created_at);
    Event {
        v: SCHEMA_VERSION,
        ts: now,
        install: install_id(),
        engine: env!("CARGO_PKG_VERSION").to_string(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        event: kind.to_string(),
        machine: machine_token(name),
        parent: record.golden.as_deref().map(machine_token),
        depth,
        branchable: Some(record.forkable),
        cuda: Some(record.cuda),
        gpu: record.gpu,
        network: Some(record.network),
        image_host,
        image_pinned,
        cpus: Some(record.cpus),
        mem_mib: Some(record.mem),
        mounts: Some(record.mounts.len()),
        ports: Some(record.ports.len()),
        age_secs,
        from: None,
        to: None,
    }
}

/// Append one event. Never fails; never blocks on anything but the local file.
pub fn record(event: &Event) {
    if !recording_enabled() {
        return;
    }
    let Some(path) = journal_path() else {
        return;
    };
    let Ok(line) = serde_json::to_string(event) else {
        return;
    };
    if let Some(dir) = path.parent() {
        if std::fs::create_dir_all(dir).is_err() {
            return;
        }
    }
    if let Ok(meta) = std::fs::metadata(&path) {
        if meta.len() > ROTATE_BYTES {
            if let Some(rotated) = rotated_path() {
                let _ = std::fs::rename(&path, rotated);
            }
        }
    }
    let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    else {
        return;
    };
    let _ = writeln!(file, "{line}");
}

/// A machine record was inserted: a `create`, or a `branch` when it has a source.
pub fn on_insert(name: &str, record: &VmRecord, parent_of: &dyn Fn(&str) -> Option<String>) {
    if !recording_enabled() {
        return;
    }
    let kind = if record.golden.is_some() {
        "branch"
    } else {
        "create"
    };
    let depth = if record.golden.is_some() {
        Some(depth_of(name, parent_of))
    } else {
        Some(0)
    };
    record_event(event_for(kind, name, record, depth));
}

/// A machine record was deleted.
pub fn on_remove(name: &str, record: &VmRecord) {
    if !recording_enabled() {
        return;
    }
    record_event(event_for("delete", name, record, None));
}

/// A record was updated in place: emit a transition when state or size changed.
pub fn on_update(name: &str, before: &VmRecord, after: &VmRecord) {
    if !recording_enabled() {
        return;
    }
    use crate::config::RecordState as S;
    if before.state != after.state {
        let kind = match (&before.state, &after.state) {
            (S::Paused, S::Running) => "resume",
            (_, S::Running) => "start",
            (_, S::Stopped) => "stop",
            (_, S::Paused) => "pause",
            (_, S::Pausing) | (_, S::Created) => return,
            _ => "error",
        };
        let mut event = event_for(kind, name, after, None);
        event.from = Some(state_name(&before.state));
        event.to = Some(state_name(&after.state));
        record_event(event);
    }
    if before.cpus != after.cpus || before.mem != after.mem {
        let mut event = event_for("resize", name, after, None);
        event.from = Some(format!("{}c/{}m", before.cpus, before.mem));
        event.to = Some(format!("{}c/{}m", after.cpus, after.mem));
        record_event(event);
    }
}

/// A checkpoint was written for (or a machine restored from) a stored image.
pub fn on_checkpoint(name: &str, record: Option<&VmRecord>) {
    on_simple("checkpoint", name, record);
}

/// A machine was restored from a checkpoint.
pub fn on_restore(name: &str, record: Option<&VmRecord>) {
    on_simple("restore", name, record);
}

fn on_simple(kind: &str, name: &str, record: Option<&VmRecord>) {
    if !recording_enabled() {
        return;
    }
    let event = match record {
        Some(record) => event_for(kind, name, record, None),
        None => Event {
            v: SCHEMA_VERSION,
            ts: now_ms(),
            install: install_id(),
            engine: env!("CARGO_PKG_VERSION").to_string(),
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            event: kind.to_string(),
            machine: machine_token(name),
            parent: None,
            depth: None,
            branchable: None,
            cuda: None,
            gpu: None,
            network: None,
            image_host: None,
            image_pinned: None,
            cpus: None,
            mem_mib: None,
            mounts: None,
            ports: None,
            age_secs: None,
            from: None,
            to: None,
        },
    };
    record_event(event);
}

fn record_event(event: Event) {
    record(&event);
}

/// Read every event in the journal (rotated file first), oldest first.
pub fn read_events() -> Vec<Event> {
    let mut events = Vec::new();
    for path in [rotated_path(), journal_path()].into_iter().flatten() {
        let Ok(file) = std::fs::File::open(&path) else {
            continue;
        };
        for line in std::io::BufReader::new(file).lines().map_while(Result::ok) {
            if let Ok(event) = serde_json::from_str::<Event>(&line) {
                events.push(event);
            }
        }
    }
    events
}

/// Delete the journal and the share offset; the install id is kept.
pub fn clear() -> std::io::Result<()> {
    for path in [journal_path(), rotated_path(), offset_path()]
        .into_iter()
        .flatten()
    {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Aggregate view of a journal.
#[derive(Debug, Default, Serialize)]
pub struct Summary {
    /// Total events read.
    pub events: usize,
    /// Oldest event time, ms.
    pub first_ts: Option<u64>,
    /// Newest event time, ms.
    pub last_ts: Option<u64>,
    /// Distinct UTC days with at least one event.
    pub days_active: usize,
    /// Event counts by kind.
    pub by_event: BTreeMap<String, usize>,
    /// Distinct machine tokens seen.
    pub machines: usize,
    /// Machines that were branched at least once.
    pub branch_sources: usize,
    /// Branch events.
    pub branches: usize,
    /// How many children each source fanned out to: min, median, max.
    pub fanout: Option<(usize, usize, usize)>,
    /// Branch count by tree depth.
    pub depth_histogram: BTreeMap<usize, usize>,
    /// Deepest branch seen.
    pub max_depth: usize,
    /// Create and branch counts by image registry host.
    pub image_hosts: BTreeMap<String, usize>,
    /// Machines with CUDA.
    pub cuda_machines: usize,
    /// Machines with egress.
    pub networked_machines: usize,
    /// Lifetime at delete, seconds: min, median, max.
    pub lifetime_secs: Option<(u64, u64, u64)>,
    /// Resize events.
    pub resizes: usize,
    /// Checkpoint events.
    pub checkpoints: usize,
    /// Restore events.
    pub restores: usize,
}

/// Aggregate a list of events.
pub fn summarize(events: &[Event]) -> Summary {
    let mut s = Summary {
        events: events.len(),
        ..Summary::default()
    };
    let mut machines = std::collections::HashSet::new();
    let mut cuda = std::collections::HashSet::new();
    let mut networked = std::collections::HashSet::new();
    let mut children_per_source: BTreeMap<String, usize> = BTreeMap::new();
    let mut days = std::collections::HashSet::new();
    let mut lifetimes = Vec::new();
    for e in events {
        s.first_ts = Some(s.first_ts.map_or(e.ts, |t| t.min(e.ts)));
        s.last_ts = Some(s.last_ts.map_or(e.ts, |t| t.max(e.ts)));
        days.insert(e.ts / 86_400_000);
        *s.by_event.entry(e.event.clone()).or_default() += 1;
        machines.insert(e.machine.clone());
        if e.cuda == Some(true) {
            cuda.insert(e.machine.clone());
        }
        if e.network == Some(true) {
            networked.insert(e.machine.clone());
        }
        match e.event.as_str() {
            "create" | "branch" => {
                if let Some(host) = &e.image_host {
                    *s.image_hosts.entry(host.clone()).or_default() += 1;
                }
                if e.event == "branch" {
                    s.branches += 1;
                    if let Some(parent) = &e.parent {
                        *children_per_source.entry(parent.clone()).or_default() += 1;
                    }
                    if let Some(depth) = e.depth {
                        *s.depth_histogram.entry(depth).or_default() += 1;
                        s.max_depth = s.max_depth.max(depth);
                    }
                }
            }
            "delete" => {
                if let Some(age) = e.age_secs {
                    lifetimes.push(age);
                }
            }
            "resize" => s.resizes += 1,
            "checkpoint" => s.checkpoints += 1,
            "restore" => s.restores += 1,
            _ => {}
        }
    }
    s.days_active = days.len();
    s.machines = machines.len();
    s.cuda_machines = cuda.len();
    s.networked_machines = networked.len();
    s.branch_sources = children_per_source.len();
    s.fanout = min_median_max(children_per_source.values().copied().collect());
    s.lifetime_secs = min_median_max(lifetimes);
    s
}

fn min_median_max<T: Ord + Copy>(mut values: Vec<T>) -> Option<(T, T, T)> {
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    let min = values[0];
    let max = values[values.len() - 1];
    let median = values[values.len() / 2];
    Some((min, median, max))
}

fn offset_path() -> Option<PathBuf> {
    journal_dir().map(|d| d.join("shared_offset"))
}

fn last_share_path() -> Option<PathBuf> {
    journal_dir().map(|d| d.join("last_share_ts"))
}

/// Outcome of a share attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareReport {
    /// Events posted in this attempt.
    pub sent: usize,
    /// Endpoint they went to.
    pub endpoint: String,
}

/// Post every event not yet shared to the configured endpoint, then advance
/// the offset. Uses the number of events as the offset, counting the rotated
/// file first, which is stable until a rotation drops old events; a rotation
/// resets the offset so at worst a batch is resent, never silently skipped.
pub fn share_now(
    settings: &UsageSection,
    timeout: std::time::Duration,
) -> std::io::Result<ShareReport> {
    let events = read_events();
    let endpoint = settings.endpoint().to_string();
    let sent_before = offset_path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or(0)
        .min(events.len());
    let pending = &events[sent_before..];
    if pending.is_empty() {
        return Ok(ShareReport { sent: 0, endpoint });
    }
    let body = serde_json::json!({
        "install": install_id(),
        "schema": SCHEMA_VERSION,
        "events": pending,
    });
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(std::io::Error::other)?;
    let endpoint_for_post = endpoint.clone();
    let status = runtime.block_on(async move {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(std::io::Error::other)?;
        client
            .post(&endpoint_for_post)
            .json(&body)
            .send()
            .await
            .map(|r| r.status())
            .map_err(std::io::Error::other)
    })?;
    if !status.is_success() {
        return Err(std::io::Error::other(format!(
            "usage endpoint {endpoint} answered {status}"
        )));
    }
    if let Some(path) = offset_path() {
        let _ = std::fs::write(path, format!("{}\n", events.len()));
    }
    if let Some(path) = last_share_path() {
        let _ = std::fs::write(path, format!("{}\n", now_ms() / 1000));
    }
    Ok(ShareReport {
        sent: pending.len(),
        endpoint,
    })
}

/// Share from a CLI exit path: only when sharing is on, at most hourly, and
/// quietly. Errors are swallowed; the next run retries.
pub fn share_if_due() {
    let Ok(settings) = crate::settings::SmolSettings::load() else {
        return;
    };
    if !settings.usage.share_enabled() || !recording_enabled() {
        return;
    }
    let last = last_share_path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0);
    if (now_ms() / 1000).saturating_sub(last) < AUTO_SHARE_INTERVAL_SECS {
        return;
    }
    let _ = share_now(&settings.usage, std::time::Duration::from_secs(3));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RecordState;

    fn record_named(name: &str, golden: Option<&str>) -> VmRecord {
        let mut record = VmRecord::new(name.to_string(), 2, 1024, Vec::new(), Vec::new(), true);
        record.golden = golden.map(str::to_string);
        record.image = Some("ghcr.io/acme/tool:1.2@sha256:abc".to_string());
        record
    }

    /// The journal directory comes from a process-wide env var, so tests that
    /// set it must not overlap.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_journal<T>(f: impl FnOnce(&std::path::Path) -> T) -> T {
        let _serial = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempfile::tempdir().expect("tempdir");
        let _guard = EnvGuard::set("SMOLVM_USAGE_DIR", dir.path());
        f(dir.path())
    }

    /// The journal's events for these machines only. The journal directory is process-wide (`SMOLVM_USAGE_DIR`), and
    /// other tests in this binary create and branch machines while one of these runs: an extra "branch" from one of them
    /// failed the release build on the shared runner.
    fn events_of(names: &[&str]) -> Vec<Event> {
        let tokens: Vec<String> = names.iter().map(|n| machine_token(n)).collect();
        read_events()
            .into_iter()
            .filter(|e| tokens.contains(&e.machine))
            .collect()
    }

    struct EnvGuard(&'static str);
    impl EnvGuard {
        fn set(key: &'static str, value: &std::path::Path) -> Self {
            std::env::set_var(key, value);
            Self(key)
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            std::env::remove_var(self.0);
        }
    }

    #[test]
    fn image_host_keeps_only_the_registry() {
        assert_eq!(
            image_host("python:3.12-slim"),
            ("docker.io".to_string(), false)
        );
        assert_eq!(
            image_host("ghcr.io/acme/tool:1.2@sha256:abc"),
            ("ghcr.io".to_string(), true)
        );
        assert_eq!(
            image_host("localhost:5000/x/y"),
            ("localhost:5000".to_string(), false)
        );
        assert_eq!(
            image_host("library/debian"),
            ("docker.io".to_string(), false)
        );
        assert_eq!(image_host("local:myimage"), ("local".to_string(), false));
    }

    #[test]
    fn depth_walks_parents_and_stops_on_cycles() {
        let parents = |n: &str| match n {
            "c" => Some("b".to_string()),
            "b" => Some("a".to_string()),
            "x" => Some("y".to_string()),
            "y" => Some("x".to_string()),
            _ => None,
        };
        assert_eq!(depth_of("a", &parents), 0);
        assert_eq!(depth_of("c", &parents), 2);
        assert!(depth_of("x", &parents) <= 2);
    }

    #[test]
    fn event_carries_shape_not_identity() {
        with_journal(|_| {
            let record = record_named("my-secret-project", Some("golden-name"));
            let event = event_for("branch", "my-secret-project", &record, Some(1));
            let json = serde_json::to_string(&event).unwrap();
            assert!(!json.contains("my-secret-project"));
            assert!(!json.contains("golden-name"));
            assert!(!json.contains("acme"));
            assert_eq!(event.image_host.as_deref(), Some("ghcr.io"));
            assert_eq!(event.image_pinned, Some(true));
            assert_eq!(event.machine, machine_token("my-secret-project"));
            assert_eq!(
                event.parent.as_deref(),
                Some(machine_token("golden-name").as_str())
            );
            assert_eq!(event.machine.len(), 16);
        });
    }

    #[test]
    fn journal_round_trips_and_summarizes() {
        with_journal(|dir| {
            let parents = |n: &str| match n {
                "child-1" | "child-2" => Some("root".to_string()),
                "grandchild" => Some("child-1".to_string()),
                _ => None,
            };
            on_insert("root", &record_named("root", None), &parents);
            on_insert("child-1", &record_named("child-1", Some("root")), &parents);
            on_insert("child-2", &record_named("child-2", Some("root")), &parents);
            on_insert(
                "grandchild",
                &record_named("grandchild", Some("child-1")),
                &parents,
            );
            let mut before = record_named("root", None);
            let mut after = before.clone();
            after.state = RecordState::Running;
            on_update("root", &before, &after);
            before = after.clone();
            after.mem = 4096;
            on_update("root", &before, &after);
            on_checkpoint("root", Some(&after));
            on_remove("child-2", &record_named("child-2", Some("root")));

            assert!(dir.join("events.jsonl").is_file());
            let events = events_of(&["root", "child-1", "child-2", "grandchild"]);
            let kinds: Vec<&str> = events.iter().map(|e| e.event.as_str()).collect();
            assert_eq!(
                kinds,
                [
                    "create",
                    "branch",
                    "branch",
                    "branch",
                    "start",
                    "resize",
                    "checkpoint",
                    "delete"
                ]
            );
            let summary = summarize(&events);
            assert_eq!(summary.branches, 3);
            assert_eq!(summary.branch_sources, 2);
            assert_eq!(summary.max_depth, 2);
            assert_eq!(summary.depth_histogram.get(&1), Some(&2));
            assert_eq!(summary.depth_histogram.get(&2), Some(&1));
            assert_eq!(summary.fanout, Some((1, 2, 2)));
            assert_eq!(summary.resizes, 1);
            assert_eq!(summary.checkpoints, 1);
            assert_eq!(summary.image_hosts.get("ghcr.io"), Some(&4));
            assert_eq!(summary.machines, 4);

            clear().unwrap();
            assert!(events_of(&["root", "child-1", "child-2", "grandchild"]).is_empty());
        });
    }

    #[test]
    fn state_transitions_map_to_verbs() {
        with_journal(|_| {
            let base = record_named("m", None);
            let mut running = base.clone();
            running.state = RecordState::Running;
            let mut paused = base.clone();
            paused.state = RecordState::Paused;
            let mut stopped = base.clone();
            stopped.state = RecordState::Stopped;
            on_update("m", &base, &running);
            on_update("m", &running, &paused);
            on_update("m", &paused, &running);
            on_update("m", &running, &stopped);
            on_update("m", &stopped, &stopped);
            let kinds: Vec<String> = events_of(&["m"]).into_iter().map(|e| e.event).collect();
            assert_eq!(kinds, ["start", "pause", "resume", "stop"]);
        });
    }

    #[test]
    fn disabled_dir_records_nothing() {
        let _serial = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _guard = EnvGuard::set("SMOLVM_USAGE_DIR", std::path::Path::new(""));
        assert!(journal_dir().is_none());
        on_insert("m", &record_named("m", None), &|_| None);
        assert!(read_events().is_empty());
    }

    #[test]
    fn section_defaults() {
        let section = UsageSection::default();
        assert!(section.record_enabled());
        assert!(!section.share_enabled());
        assert_eq!(section.endpoint(), DEFAULT_SHARE_ENDPOINT);
        let custom = UsageSection {
            record: Some(false),
            share: Some(true),
            endpoint: Some("https://example.test/u".into()),
        };
        assert!(!custom.record_enabled());
        assert!(custom.share_enabled());
        assert_eq!(custom.endpoint(), "https://example.test/u");
    }
}
