//! `docker events`: what happened to containers, images, volumes and networks.

use std::collections::{BTreeMap, VecDeque};

use serde::Serialize;

use super::filters::Filters;

/// Events kept for clients that ask for `since` in the past.
const HISTORY: usize = 2048;

/// One event, in the shape the Docker API streams.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Event {
    #[serde(rename = "Type")]
    pub kind: &'static str,
    #[serde(rename = "Action")]
    pub action: String,
    #[serde(rename = "Actor")]
    pub actor: Actor,
    pub scope: &'static str,
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
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Actor {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "Attributes")]
    pub attributes: BTreeMap<String, String>,
}

/// The event bus: a broadcast channel plus a short history.
pub(crate) struct Events {
    sender: tokio::sync::broadcast::Sender<Event>,
    history: parking_lot::Mutex<VecDeque<Event>>,
}

impl Events {
    pub(crate) fn new() -> Self {
        let (sender, _) = tokio::sync::broadcast::channel(1024);
        Self {
            sender,
            history: parking_lot::Mutex::new(VecDeque::with_capacity(HISTORY)),
        }
    }

    /// Record and broadcast an event.
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
            kind,
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
            scope: "local",
            time: now.as_secs() as i64,
            time_nano: now.as_nanos() as i64,
        };
        {
            let mut history = self.history.lock();
            if history.len() == HISTORY {
                history.pop_front();
            }
            history.push_back(event.clone());
        }
        let _ = self.sender.send(event);
    }

    pub(crate) fn subscribe(&self) -> tokio::sync::broadcast::Receiver<Event> {
        self.sender.subscribe()
    }

    /// Past events at or after `since_nanos`.
    pub(crate) fn since(&self, since_nanos: i64) -> Vec<Event> {
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
