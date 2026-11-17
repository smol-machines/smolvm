//! Small shared pieces: errors in Docker's shape, ids, names, timestamps.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// An API error, answered as Docker answers them: a status and
/// `{"message": "..."}`.
#[derive(Debug)]
pub(crate) struct ApiError {
    pub status: StatusCode,
    pub message: String,
}

impl ApiError {
    pub(crate) fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
    pub(crate) fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }
    pub(crate) fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }
    pub(crate) fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, message)
    }
    pub(crate) fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, message)
    }
    pub(crate) fn not_implemented(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_IMPLEMENTED, message)
    }
    pub(crate) fn no_such_container(name: &str) -> Self {
        Self::not_found(format!("No such container: {name}"))
    }
}

impl From<crate::Error> for ApiError {
    fn from(e: crate::Error) -> Self {
        Self::internal(e.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            serde_json::json!({ "message": self.message }).to_string(),
        )
            .into_response()
    }
}

/// Result type of handlers.
pub(crate) type ApiResult<T> = Result<T, ApiError>;

/// Drop every `null` member of every object in `value`. Clients send `null`
/// for "not set" (docker-java does for every unset number), which means the
/// same as leaving the field out.
pub(crate) fn strip_nulls(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            map.retain(|_, v| !v.is_null());
            for v in map.values_mut() {
                strip_nulls(v);
            }
        }
        serde_json::Value::Array(list) => {
            for v in list {
                strip_nulls(v);
            }
        }
        _ => {}
    }
}

/// A request body, `null` members read as absent. An empty body is the
/// default value.
pub(crate) fn parse_body<T: serde::de::DeserializeOwned + Default>(body: &[u8]) -> ApiResult<T> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(T::default());
    }
    let mut value: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| ApiError::bad_request(format!("invalid JSON: {e}")))?;
    strip_nulls(&mut value);
    serde_json::from_value(value)
        .map_err(|e| ApiError::bad_request(format!("invalid request: {e}")))
}

/// A new 64-hex-digit object id, as Docker's are.
pub(crate) fn new_id() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("system randomness");
    hex::encode(bytes)
}

/// `t` as RFC 3339 with nanoseconds, the format Docker timestamps use.
pub(crate) fn rfc3339(t: std::time::SystemTime) -> String {
    humantime::format_rfc3339_nanos(t).to_string()
}

/// The current time as [`rfc3339`].
pub(crate) fn now_rfc3339() -> String {
    rfc3339(std::time::SystemTime::now())
}

/// Docker's zero time, used for "never".
pub(crate) const ZERO_TIME: &str = "0001-01-01T00:00:00Z";

/// Seconds since the epoch of an RFC 3339 timestamp; 0 when unparsable.
pub(crate) fn unix_seconds(ts: &str) -> i64 {
    humantime::parse_rfc3339_weak(ts)
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A `since`/`until` query value: Unix seconds (with optional fraction),
/// an RFC 3339 timestamp, or a duration back from now (`10m`).
pub(crate) fn parse_time_filter(value: &str) -> Option<std::time::SystemTime> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if let Ok(secs) = value.parse::<f64>() {
        return Some(std::time::UNIX_EPOCH + std::time::Duration::from_secs_f64(secs.max(0.0)));
    }
    if let Ok(t) = humantime::parse_rfc3339_weak(value) {
        return Some(t);
    }
    humantime::parse_duration(value)
        .ok()
        .and_then(|d| std::time::SystemTime::now().checked_sub(d))
}

/// A random `adjective_surname` container name, like Docker's.
pub(crate) fn random_name() -> String {
    const LEFT: &[&str] = &[
        "admiring",
        "agitated",
        "amazing",
        "bold",
        "brave",
        "busy",
        "charming",
        "clever",
        "compassionate",
        "competent",
        "condescending",
        "confident",
        "cool",
        "dazzling",
        "determined",
        "eager",
        "ecstatic",
        "elastic",
        "elated",
        "elegant",
        "epic",
        "exciting",
        "festive",
        "focused",
        "friendly",
        "frosty",
        "funny",
        "gallant",
        "gifted",
        "goofy",
        "gracious",
        "happy",
        "hopeful",
        "hungry",
        "inspiring",
        "intelligent",
        "interesting",
        "jolly",
        "keen",
        "kind",
        "laughing",
        "loving",
        "lucid",
        "magical",
        "modest",
        "musing",
        "nice",
        "nifty",
        "nostalgic",
        "objective",
        "optimistic",
        "peaceful",
        "pensive",
        "practical",
        "priceless",
        "quirky",
        "quizzical",
        "relaxed",
        "reverent",
        "romantic",
        "serene",
        "sharp",
        "silly",
        "sleepy",
        "stoic",
        "sweet",
        "tender",
        "thirsty",
        "trusting",
        "upbeat",
        "vibrant",
        "vigilant",
        "wizardly",
        "wonderful",
        "xenodochial",
        "youthful",
        "zealous",
        "zen",
    ];
    const RIGHT: &[&str] = &[
        "agnesi",
        "albattani",
        "allen",
        "archimedes",
        "ardinghelli",
        "babbage",
        "banach",
        "bardeen",
        "bartik",
        "bassi",
        "bell",
        "benz",
        "bhabha",
        "blackwell",
        "bohr",
        "booth",
        "borg",
        "bose",
        "brahmagupta",
        "brattain",
        "brown",
        "carson",
        "cerf",
        "chandrasekhar",
        "clarke",
        "curie",
        "darwin",
        "davinci",
        "dijkstra",
        "einstein",
        "elion",
        "engelbart",
        "euclid",
        "euler",
        "faraday",
        "fermat",
        "fermi",
        "feynman",
        "franklin",
        "galileo",
        "gauss",
        "goldberg",
        "goodall",
        "hamilton",
        "hawking",
        "heisenberg",
        "hodgkin",
        "hopper",
        "hypatia",
        "jackson",
        "jennings",
        "johnson",
        "kalam",
        "kepler",
        "khorana",
        "knuth",
        "lamarr",
        "leakey",
        "lovelace",
        "lumiere",
        "mayer",
        "mccarthy",
        "mcclintock",
        "meitner",
        "mendel",
        "morse",
        "napier",
        "newton",
        "noether",
        "pascal",
        "pasteur",
        "perlman",
        "pike",
        "poincare",
        "ramanujan",
        "ride",
        "ritchie",
        "rosalind",
        "sammet",
        "shannon",
        "shockley",
        "sinoussi",
        "stallman",
        "swanson",
        "tesla",
        "thompson",
        "torvalds",
        "turing",
        "volhard",
        "wescoff",
        "wiles",
        "williams",
        "wilson",
        "wozniak",
        "wright",
        "yalow",
    ];
    let mut bytes = [0u8; 4];
    getrandom::fill(&mut bytes).expect("system randomness");
    let left = LEFT[(u16::from_le_bytes([bytes[0], bytes[1]]) as usize) % LEFT.len()];
    let right = RIGHT[(u16::from_le_bytes([bytes[2], bytes[3]]) as usize) % RIGHT.len()];
    format!("{left}_{right}")
}

/// Whether `name` is a valid container name: Docker's `[a-zA-Z0-9][a-zA-Z0-9_.-]+`.
pub(crate) fn valid_container_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphanumeric())
        && name.len() >= 2
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// A signal name or number as Docker accepts it (`SIGKILL`, `KILL`, `9`),
/// returned as the number. `None` for an unknown signal.
pub(crate) fn signal_number(signal: &str) -> Option<i32> {
    let s = signal.trim();
    if let Ok(n) = s.parse::<i32>() {
        return (1..=64).contains(&n).then_some(n);
    }
    let upper = s.to_ascii_uppercase();
    let name = upper.strip_prefix("SIG").unwrap_or(&upper);
    Some(match name {
        "HUP" => 1,
        "INT" => 2,
        "QUIT" => 3,
        "ILL" => 4,
        "TRAP" => 5,
        "ABRT" | "IOT" => 6,
        "BUS" => 7,
        "FPE" => 8,
        "KILL" => 9,
        "USR1" => 10,
        "SEGV" => 11,
        "USR2" => 12,
        "PIPE" => 13,
        "ALRM" => 14,
        "TERM" => 15,
        "STKFLT" => 16,
        "CHLD" => 17,
        "CONT" => 18,
        "STOP" => 19,
        "TSTP" => 20,
        "TTIN" => 21,
        "TTOU" => 22,
        "URG" => 23,
        "XCPU" => 24,
        "XFSZ" => 25,
        "VTALRM" => 26,
        "PROF" => 27,
        "WINCH" => 28,
        "IO" | "POLL" => 29,
        "PWR" => 30,
        "SYS" => 31,
        other => {
            let n = other
                .strip_prefix("RTMIN+")
                .and_then(|n| n.parse::<i32>().ok())
                .map(|n| 34 + n)
                .or_else(|| (other == "RTMIN").then_some(34))?;
            return (n <= 64).then_some(n);
        }
    })
}

/// This host's architecture as images name it (`arm64`, `amd64`).
pub(crate) fn host_arch() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "amd64",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signals_by_name_or_number() {
        assert_eq!(signal_number("SIGKILL"), Some(9));
        assert_eq!(signal_number("term"), Some(15));
        assert_eq!(signal_number("9"), Some(9));
        assert_eq!(signal_number("SIGRTMIN+3"), Some(37));
        assert_eq!(signal_number("NOPE"), None);
    }

    #[test]
    fn container_names_follow_docker() {
        assert!(valid_container_name("web-1"));
        assert!(valid_container_name("project_db_1"));
        assert!(!valid_container_name("-web"));
        assert!(!valid_container_name("a"));
        assert!(!valid_container_name("we b"));
    }

    #[test]
    fn nulls_read_as_absent() {
        #[derive(serde::Deserialize, Default)]
        #[serde(default, rename_all = "PascalCase")]
        struct T {
            memory: i64,
            name: String,
        }
        let t: T = parse_body(br#"{"Memory": null, "Name": "x", "Nested": {"A": null}}"#).unwrap();
        assert_eq!(t.memory, 0);
        assert_eq!(t.name, "x");
        let t: T = parse_body(b"  ").unwrap();
        assert_eq!(t.name, "");
    }

    #[test]
    fn time_filters() {
        assert_eq!(
            parse_time_filter("10"),
            Some(std::time::UNIX_EPOCH + std::time::Duration::from_secs(10))
        );
        assert!(parse_time_filter("5m").is_some());
        assert!(parse_time_filter("2026-01-02T03:04:05Z").is_some());
    }
}
