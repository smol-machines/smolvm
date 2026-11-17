//! `docker events`: what happened to containers, images, volumes and networks.

use std::collections::{BTreeMap, VecDeque};

use serde::{Deserialize, Serialize};

use super::filters::Filters;

/// Events kept for clients that ask for `since` in the past.
const HISTORY: usize = 2048;

/// One event, in the shape the Docker API streams.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Event {
    #[serde(skip)]
    pub cursor: String,
    #[serde(rename = "Type")]
    pub kind: String,
    #[serde(rename = "Action")]
    pub action: String,
    #[serde(rename = "Actor")]
    pub actor: Actor,
    pub scope: String,
    pub time: i64,
    #[serde(rename = "timeNano")]
    pub time_nano: i64,
    // The pre-1.22 fields, still read by some clients.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
}

/// The object an event is about.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Actor {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "Attributes")]
    pub attributes: BTreeMap<String, String>,
}

/// A bounded history shared by the adapter and workload supervisors.
pub(crate) struct Events {
    root: Option<std::path::PathBuf>,
    history: parking_lot::Mutex<VecDeque<Event>>,
}

impl Events {
    pub(crate) fn persistent(root: &std::path::Path) -> crate::Result<Self> {
        let dir = root.join("events");
        std::fs::create_dir_all(&dir)?;
        let mut events = Self::new();
        events.root = Some(dir);
        Ok(events)
    }

    pub(crate) fn new() -> Self {
        Self {
            root: None,
            history: parking_lot::Mutex::new(VecDeque::with_capacity(HISTORY)),
        }
    }

    /// Persist an event for current subscribers and reconnecting clients.
    pub(crate) fn emit(
        &self,
        kind: &'static str,
        action: impl Into<String>,
        id: &str,
        attributes: BTreeMap<String, String>,
    ) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let action = action.into();
        let container = kind == "container";
        let event = Event {
            cursor: super::util::new_id(),
            kind: kind.into(),
            status: container.then(|| action.clone()),
            id: container.then(|| id.to_string()),
            from: container
                .then(|| attributes.get("image").cloned())
                .flatten(),
            action,
            actor: Actor {
                id: id.to_string(),
                attributes,
            },
            scope: "local".into(),
            time: now.as_secs() as i64,
            time_nano: now.as_nanos() as i64,
        };
        if let Some(root) = &self.root {
            let name = format!("{}-{}.json", event.time_nano, event.cursor);
            let path = root.join(name);
            let temp = path.with_extension("tmp");
            if let Ok(bytes) = serde_json::to_vec(&event) {
                if std::fs::write(&temp, bytes).is_ok() {
                    let _ = std::fs::rename(temp, path);
                }
            }
        }
        {
            let mut history = self.history.lock();
            if history.len() == HISTORY {
                history.pop_front();
            }
            history.push_back(event.clone());
        }
    }

    /// Past events at or after `since_nanos`.
    pub(crate) fn since(&self, since_nanos: i64) -> Vec<Event> {
        if let Some(root) = &self.root {
            let mut paths: Vec<_> = std::fs::read_dir(root)
                .into_iter()
                .flatten()
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|s| s == "json"))
                .collect();
            paths.sort();
            let excess = paths.len().saturating_sub(HISTORY);
            for path in &paths[..excess] {
                let _ = std::fs::remove_file(path);
            }
            return paths[excess..]
                .iter()
                .filter_map(|p| {
                    let name = p.file_name()?.to_str()?;
                    let timestamp: i64 = name.split_once('-')?.0.parse().ok()?;
                    if timestamp < since_nanos {
                        return None;
                    }
                    let bytes = std::fs::read(p).ok()?;
                    let mut event: Event = serde_json::from_slice(&bytes).ok()?;
                    event.cursor = p.file_name()?.to_string_lossy().into_owned();
                    Some(event)
                })
                .filter(|e| e.time_nano >= since_nanos)
                .collect();
        }
        self.history
            .lock()
            .iter()
            .filter(|e| e.time_nano >= since_nanos)
            .cloned()
            .collect()
    }
}

/// Whether `event` passes the `docker events` filters.
pub(crate) fn matches(event: &Event, filters: &Filters) -> bool {
    let attrs = &event.actor.attributes;
    let name = attrs.get("name").map(String::as_str).unwrap_or("");
    filters.any("type", |t| t == event.kind)
        && filters.any("event", |e| {
            e == event.action || event.action.split(':').next() == Some(e)
        })
        && filters.any("container", |c| {
            event.kind == "container" && (event.actor.id.starts_with(c) || name == c)
        })
        && filters.any("image", |i| {
            attrs.get("image").is_some_and(|img| img == i)
                || (event.kind == "image" && event.actor.id == i)
        })
        && filters.any("network", |n| {
            event.kind == "network" && (event.actor.id.starts_with(n) || name == n)
        })
        && filters.any("volume", |v| event.kind == "volume" && event.actor.id == v)
        && filters.labels_match("label", attrs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_by_type_action_and_label() {
        let events = Events::new();
        let mut attrs = BTreeMap::new();
        attrs.insert("name".into(), "web".into());
        attrs.insert("com.docker.compose.project".into(), "demo".into());
        events.emit("container", "health_status: healthy", "abc", attrs);
        let e = &events.since(0)[0];
        let f = Filters::parse(Some(
            r#"{"type":["container"],"event":["health_status"],"label":["com.docker.compose.project=demo"]}"#,
        ))
        .unwrap();
        assert!(matches(e, &f));
        let f = Filters::parse(Some(r#"{"container":["other"]}"#)).unwrap();
        assert!(!matches(e, &f));
    }
}

#[cfg(test)]
mod persistence_tests {
    use super::*;
    #[test]
    fn independent_process_views_recover_events_after_the_emitter_goes_away() {
        let root = tempfile::tempdir().unwrap();
        let writer = Events::persistent(root.path()).unwrap();
        writer.emit("container", "start", "one", BTreeMap::new());
        drop(writer);
        let reader = Events::persistent(root.path()).unwrap();
        let events = reader.since(0);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].actor.id, "one");
        assert!(!events[0].cursor.is_empty());
        assert!(serde_json::to_value(&events[0])
            .unwrap()
            .get("cursor")
            .is_none());
    }
}
