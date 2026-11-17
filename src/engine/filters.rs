//! The `filters` query parameter every list endpoint takes.

use std::collections::{BTreeMap, HashMap};

/// Parsed filters: each key with the values a client gave for it. A value
/// matches when ANY of its key's values matches; every key must match.
#[derive(Debug, Default, Clone)]
pub(crate) struct Filters {
    map: HashMap<String, Vec<String>>,
}

impl Filters {
    /// Parse the JSON a client sends: `{"label":{"a=b":true}}`, or the older
    /// `{"label":["a=b"]}`.
    pub(crate) fn parse(raw: Option<&str>) -> Result<Self, String> {
        let Some(raw) = raw.filter(|r| !r.trim().is_empty()) else {
            return Ok(Self::default());
        };
        let value: serde_json::Value =
            serde_json::from_str(raw).map_err(|e| format!("invalid filters: {e}"))?;
        let mut map: HashMap<String, Vec<String>> = HashMap::new();
        let Some(object) = value.as_object() else {
            return Err("invalid filters: not an object".into());
        };
        for (key, values) in object {
            let entry = map.entry(key.clone()).or_default();
            match values {
                serde_json::Value::Object(set) => {
                    for (v, on) in set {
                        if on.as_bool().unwrap_or(true) {
                            entry.push(v.clone());
                        }
                    }
                }
                serde_json::Value::Array(list) => {
                    entry.extend(list.iter().filter_map(|v| v.as_str().map(str::to_string)));
                }
                serde_json::Value::String(s) => entry.push(s.clone()),
                _ => {}
            }
        }
        Ok(Self { map })
    }

    /// Values given for `key` (empty when the key is absent).
    pub(crate) fn get(&self, key: &str) -> &[String] {
        self.map.get(key).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Whether `key` was given at all.
    pub(crate) fn has(&self, key: &str) -> bool {
        self.map.get(key).is_some_and(|v| !v.is_empty())
    }

    /// `true` when `key` is absent, else whether any of its values passes `f`.
    pub(crate) fn any(&self, key: &str, f: impl Fn(&str) -> bool) -> bool {
        match self.map.get(key) {
            None => true,
            Some(values) if values.is_empty() => true,
            Some(values) => values.iter().any(|v| f(v)),
        }
    }

    /// Every `label` filter (`key` or `key=value`, or `key!=value` for the
    /// negative form) holds for `labels`. Unlike other keys, all label
    /// filters must hold.
    pub(crate) fn labels_match(&self, key: &str, labels: &BTreeMap<String, String>) -> bool {
        self.get(key).iter().all(|f| label_matches(f, labels))
    }
}

/// One label filter against a label set.
pub(crate) fn label_matches(filter: &str, labels: &BTreeMap<String, String>) -> bool {
    if let Some((k, v)) = filter.split_once("!=") {
        return labels.get(k).map(|have| have != v).unwrap_or(true);
    }
    match filter.split_once('=') {
        Some((k, v)) => labels.get(k).is_some_and(|have| have == v),
        None => labels.contains_key(filter),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_both_filter_shapes() {
        let f = Filters::parse(Some(r#"{"label":{"a=b":true},"status":["running"]}"#)).unwrap();
        assert_eq!(f.get("label"), ["a=b"]);
        assert_eq!(f.get("status"), ["running"]);
        assert!(f.any("name", |_| false));
    }

    #[test]
    fn labels_need_every_filter() {
        let f = Filters::parse(Some(
            r#"{"label":{"com.docker.compose.project=demo":true,"com.docker.compose.oneoff=False":true}}"#,
        ))
        .unwrap();
        let mut labels = BTreeMap::new();
        labels.insert("com.docker.compose.project".into(), "demo".into());
        assert!(!f.labels_match("label", &labels));
        labels.insert("com.docker.compose.oneoff".into(), "False".into());
        assert!(f.labels_match("label", &labels));
        assert!(label_matches("x!=1", &labels));
    }
}
