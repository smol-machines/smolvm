//! The `filters` query parameter every list endpoint takes.

use std::collections::{BTreeMap, HashMap};

/// Parsed filters: each key with the values a client gave for it. A value
/// matches when ANY of its key's values matches; every key must match.
#[derive(Debug, Default, Clone)]
pub(crate) struct Filters {
    map: HashMap<String, Vec<String>>,
    name_patterns: std::sync::OnceLock<Vec<Option<regex::Regex>>>,
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
        Ok(Self {
            map,
            name_patterns: Default::default(),
        })
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

    /// Docker matches name expressions against both `/name` and `name`.
    /// Cache compiled patterns for this request, not for every container, and
    /// ignore invalid expressions as Docker does (literal equality still wins).
    pub(crate) fn container_name_matches(&self, name: &str) -> bool {
        let values = self.get("name");
        if values.is_empty() {
            return true;
        }
        let name = name.strip_prefix('/').unwrap_or(name);
        let full_name = format!("/{name}");
        if values
            .iter()
            .any(|value| value == name || value == &full_name)
        {
            return true;
        }
        self.name_patterns
            .get_or_init(|| {
                values
                    .iter()
                    .map(|value| regex::Regex::new(&unquote_pattern(value)).ok())
                    .collect()
            })
            .iter()
            .flatten()
            .any(|pattern| pattern.is_match(name) || pattern.is_match(&full_name))
    }

    /// Every `label` filter (`key` or `key=value`, or `key!=value` for the
    /// negative form) holds for `labels`. Unlike other keys, all label
    /// filters must hold.
    pub(crate) fn labels_match(&self, key: &str, labels: &BTreeMap<String, String>) -> bool {
        self.get(key).iter().all(|f| label_matches(f, labels))
    }
}

// Go/RE2 accepts \Q...\E literals, including an unterminated quote to EOF.
// Preserve ordinary escapes so an escaped backslash before Q does not quote.
fn unquote_pattern(mut pattern: &str) -> String {
    let mut out = String::new();
    while let Some(index) = pattern.find('\\') {
        out.push_str(&pattern[..index]);
        pattern = &pattern[index..];
        if let Some(quoted) = pattern.strip_prefix(r"\Q") {
            match quoted.split_once(r"\E") {
                Some((literal, rest)) => {
                    out.push_str(&regex::escape(literal));
                    pattern = rest;
                }
                None => {
                    out.push_str(&regex::escape(quoted));
                    return out;
                }
            }
        } else {
            let mut chars = pattern.chars();
            out.push(chars.next().unwrap());
            if let Some(next) = chars.next() {
                out.push(next);
            }
            pattern = chars.as_str();
        }
    }
    out.push_str(pattern);
    out
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

    fn names(patterns: &[&str]) -> Filters {
        Filters::parse(Some(&serde_json::json!({"name": patterns}).to_string())).unwrap()
    }

    #[test]
    fn container_name_anchors_work_with_and_without_the_leading_slash() {
        for pattern in ["api", "/api", "^api$", "^/api$", "^/?api$"] {
            assert!(names(&[pattern]).container_name_matches("api"), "{pattern}");
        }
        for pattern in ["^api$", "^/api$", "^/?api$"] {
            for other in ["api-2", "myapi", "api.other"] {
                assert!(
                    !names(&[pattern]).container_name_matches(other),
                    "{pattern}: {other}"
                );
            }
        }
        assert!(names(&["^/api"]).container_name_matches("api-2"));
        assert!(names(&["api$"]).container_name_matches("myapi"));
        assert!(!names(&["^//api$"]).container_name_matches("api"));
    }

    #[test]
    fn container_name_patterns_support_groups_classes_and_escaped_literals() {
        let filter = names(&[r"^/?(api|web)-[0-9]+$"]);
        for name in ["api-1", "web-20"] {
            assert!(filter.container_name_matches(name));
        }
        for name in ["api", "api-x", "worker-1", "myweb-1"] {
            assert!(!filter.container_name_matches(name));
        }
        assert!(names(&[r"^/v1\.2$"]).container_name_matches("v1.2"));
        assert!(!names(&[r"^/v1\.2$"]).container_name_matches("v1x2"));
        assert!(names(&[r"(?i)^/API$"]).container_name_matches("api"));
    }

    #[test]
    fn go_quoted_literals_preserve_escapes_and_anchor_positions() {
        assert!(names(&[r"^\Q/api.v1\E$"]).container_name_matches("api.v1"));
        assert!(!names(&[r"^\Q/api.v1\E$"]).container_name_matches("apixv1"));
        assert!(names(&[r"^\Q/api.v1"]).container_name_matches("api.v1"));
        assert_eq!(unquote_pattern(r"\\Qliteral"), r"\\Qliteral");
        assert!(names(&[r"\Q/api.v1\E(-[0-9]+)?$"]).container_name_matches("api.v1-2"));
    }

    #[test]
    fn invalid_name_patterns_do_not_hide_valid_alternatives_or_literal_matches() {
        assert!(!names(&["["]).container_name_matches("api"));
        assert!(names(&["[", "^/api$"]).container_name_matches("api"));
        assert!(names(&["[", "^/api$"]).container_name_matches("["));
        assert!(Filters::default().container_name_matches("anything"));
        assert!(names(&[]).container_name_matches("anything"));
        assert!(names(&[""]).container_name_matches("anything"));
        let modern = Filters::parse(Some(
            r#"{"name":{"^/api$":true,"[":true,"^/other$":false}}"#,
        ))
        .unwrap();
        assert!(modern.container_name_matches("api"));
        assert!(!modern.container_name_matches("other"));
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
