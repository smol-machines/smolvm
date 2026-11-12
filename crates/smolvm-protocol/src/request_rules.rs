//! HTTPS request rules: per-host method and path allow/deny lists.
//!
//! Pure data and matching, no I/O. A host no rule names is
//! [`Decision::Unruled`] and the caller keeps its existing behavior. On a
//! ruled host a matching deny always wins; if the host has allow rules a
//! request must match one of them; a deny-only host allows the rest.
//!
//! Rule hosts follow [`crate::host_pattern`]'s strict forms: a bare name is an
//! exact host and `*.domain` covers subdomains only. Paths are globs over `/`
//! segments: `*` is one non-empty segment, `**` is zero or more segments.
//!
//! The request path is canonicalized before matching, so an alternate spelling
//! cannot slip past a deny: the query and fragment are dropped, `%XX` octets
//! are decoded once (an encoded `/` splits a segment; an invalid escape stays
//! literal), `.` and `..` are resolved per RFC 3986 (never above the root),
//! and repeated slashes are ignored.

use serde::{Deserialize, Serialize};

use crate::host_pattern;

/// Whether a matching rule permits or refuses the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Permit matching requests.
    Allow,
    /// Refuse matching requests, overriding any allow.
    Deny,
}

/// One request rule. Empty `methods` or `paths` mean "any".
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequestRule {
    /// Allow or deny.
    pub action: Action,
    /// Host names or `*.domain` patterns the rule applies to.
    pub hosts: Vec<String>,
    /// HTTP methods, compared case-insensitively; empty means any.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
    /// Path globs starting with `/`; empty means any path.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
}

/// Outcome of [`decide`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// No rule names this host; the caller's default applies.
    Unruled,
    /// The request may proceed.
    Allow,
    /// The request is refused, with a static reason for the response body.
    Deny(&'static str),
}

impl RequestRule {
    /// Parse the CLI form `[METHODS] HOST[/PATH]`, e.g. `GET,HEAD a.com`,
    /// `a.com/x/**` or `POST a.com/x`.
    pub fn parse(action: Action, spec: &str) -> Result<Self, String> {
        let invalid = |why: &str| format!("invalid request rule {spec:?}: {why}");
        let mut parts = spec.split_whitespace();
        let (methods, target) = match (parts.next(), parts.next(), parts.next()) {
            (Some(target), None, _) => (None, target),
            (Some(methods), Some(target), None) => (Some(methods), target),
            _ => return Err(invalid("expected [METHODS] HOST[/PATH]")),
        };
        let methods = match methods {
            None => Vec::new(),
            Some(list) => list.split(',').map(str::to_ascii_uppercase).collect(),
        };
        let (host, path) = match target.find('/') {
            Some(i) => (&target[..i], Some(&target[i..])),
            None => (target, None),
        };
        let rule = Self {
            action,
            hosts: vec![host.to_string()],
            methods,
            paths: path.map(|p| vec![p.to_string()]).unwrap_or_default(),
        };
        rule.validate().map_err(|e| invalid(&e))?;
        Ok(rule)
    }

    /// Check a rule built from a Smolfile or API body as [`Self::parse`]
    /// checks the CLI form: at least one valid host, method tokens, and paths
    /// starting with `/`, without `%`, using `*` only as a whole segment.
    pub fn validate(&self) -> Result<(), String> {
        if self.hosts.is_empty() {
            return Err("names no host".into());
        }
        for host in &self.hosts {
            host_pattern::encode_strict(host)?;
        }
        if self
            .methods
            .iter()
            .any(|m| m.is_empty() || !m.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
        {
            return Err("empty or invalid method".into());
        }
        for path in &self.paths {
            if !path.starts_with('/') {
                return Err(format!("path {path:?} must start with /"));
            }
            // Request paths are percent-decoded before matching and rule paths
            // are not, so a rule with an escape would never match (a deny
            // would fail open).
            if path.contains('%') {
                return Err(format!(
                    "path {path:?} must not contain %; write it decoded, as it is matched"
                ));
            }
            if let Some(segment) = path
                .split('/')
                .find(|s| s.contains('*') && *s != "*" && *s != "**")
            {
                return Err(format!(
                    "path {path:?}: {segment:?} is matched literally; use * or ** as a whole segment"
                ));
            }
        }
        Ok(())
    }

    fn matches_host(&self, host: &str) -> bool {
        self.hosts.iter().any(|h| {
            // Bare names are exact hosts, like `--allow-host-pattern`.
            let entry = if h.starts_with("*.") {
                h.clone()
            } else {
                format!("={h}")
            };
            host_pattern::matches(host, &entry)
        })
    }

    fn matches_request(&self, method: &str, path: &str) -> bool {
        let method_ok =
            self.methods.is_empty() || self.methods.iter().any(|m| m.eq_ignore_ascii_case(method));
        let path = path.split(['?', '#']).next().unwrap_or("");
        let path_ok = self.paths.is_empty() || self.paths.iter().any(|g| glob_matches(g, path));
        method_ok && path_ok
    }
}

/// Whether any rule names `host`, so the interceptor must terminate its TLS.
pub fn rules_name_host(rules: &[RequestRule], host: &str) -> bool {
    rules.iter().any(|r| r.matches_host(host))
}

/// Decide a request against `rules`. `host` is the TLS server name.
pub fn decide(rules: &[RequestRule], host: &str, method: &str, path: &str) -> Decision {
    let for_host: Vec<&RequestRule> = rules.iter().filter(|r| r.matches_host(host)).collect();
    if for_host.is_empty() {
        return Decision::Unruled;
    }
    let hit = |action| {
        for_host
            .iter()
            .any(|r| r.action == action && r.matches_request(method, path))
    };
    if hit(Action::Deny) {
        return Decision::Deny("smolvm: request denied by request rules");
    }
    let has_allow = for_host.iter().any(|r| r.action == Action::Allow);
    if has_allow && !hit(Action::Allow) {
        return Decision::Deny("smolvm: request denied by request rules (no allow rule matches)");
    }
    Decision::Allow
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |c: u8| (c as char).to_digit(16);
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The segments of an already percent-decoded path, with `.`, `..` and empty
/// segments resolved.
fn canonical_segments(decoded: &str) -> Vec<&str> {
    let mut out = Vec::new();
    for seg in decoded.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    out
}

/// Whether `glob` matches the whole canonical `path`. The path is the
/// guest's, so this never backtracks: it takes time proportional to glob
/// segments times path segments, however many `**` the glob has.
fn glob_matches(glob: &str, path: &str) -> bool {
    let decoded = percent_decode(path);
    let path = canonical_segments(&decoded);
    // `ends[i]`: the glob segments so far can match exactly `path[..i]`.
    let mut ends = vec![false; path.len() + 1];
    ends[0] = true;
    for segment in glob.split('/').filter(|s| !s.is_empty()) {
        let mut next = vec![false; path.len() + 1];
        if segment == "**" {
            // Zero or more segments: every position at or after a reachable one.
            let mut reachable = false;
            for (i, end) in ends.iter().enumerate() {
                reachable |= end;
                next[i] = reachable;
            }
        } else {
            for (i, part) in path.iter().enumerate() {
                next[i + 1] = ends[i] && (segment == "*" || segment == *part);
            }
        }
        ends = next;
    }
    ends[path.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow(s: &str) -> RequestRule {
        RequestRule::parse(Action::Allow, s).unwrap()
    }
    fn deny(s: &str) -> RequestRule {
        RequestRule::parse(Action::Deny, s).unwrap()
    }
    fn is_deny(d: Decision) -> bool {
        matches!(d, Decision::Deny(_))
    }

    #[test]
    fn allow_methods_on_host() {
        let rules = [allow("GET,HEAD registry.npmjs.org")];
        assert_eq!(
            decide(&rules, "registry.npmjs.org", "GET", "/x"),
            Decision::Allow
        );
        assert!(is_deny(decide(&rules, "registry.npmjs.org", "POST", "/x")));
        assert_eq!(decide(&rules, "other.org", "GET", "/x"), Decision::Unruled);
    }

    #[test]
    fn deny_only_host_allows_the_rest() {
        let rules = [deny("POST github.com/**/git-receive-pack")];
        assert!(is_deny(decide(
            &rules,
            "github.com",
            "POST",
            "/o/r.git/git-receive-pack"
        )));
        assert_eq!(
            decide(&rules, "github.com", "GET", "/o/r.git/info/refs"),
            Decision::Allow
        );
        assert_eq!(
            decide(&rules, "github.com", "POST", "/o/r/pulls"),
            Decision::Allow
        );
    }

    #[test]
    fn deny_wins_over_allow() {
        let rules = [
            allow("github.com"),
            deny("POST github.com/**/git-receive-pack"),
        ];
        assert!(is_deny(decide(
            &rules,
            "github.com",
            "POST",
            "/a/b/git-receive-pack"
        )));
        assert_eq!(
            decide(&rules, "github.com", "POST", "/a/b/other"),
            Decision::Allow
        );
    }

    #[test]
    fn globs() {
        let rules = [allow("a.com/v1/*")];
        assert_eq!(decide(&rules, "a.com", "GET", "/v1/x"), Decision::Allow);
        assert!(is_deny(decide(&rules, "a.com", "GET", "/v1/x/y")));
        assert!(is_deny(decide(&rules, "a.com", "GET", "/v1/")));
        let rules = [allow("a.com/**")];
        assert_eq!(decide(&rules, "a.com", "GET", "/"), Decision::Allow);
        assert_eq!(decide(&rules, "a.com", "GET", "/a/b/c"), Decision::Allow);
        let rules = [allow("a.com/get")];
        assert_eq!(decide(&rules, "a.com", "GET", "/get?a=1"), Decision::Allow);
        assert!(is_deny(decide(&rules, "a.com", "GET", "/get/more")));
    }

    #[test]
    fn double_stars_match_any_run_of_segments() {
        let rules = [allow("a.com/a/**/b/**/c")];
        for p in [
            "/a/b/c",
            "/a/x/b/c",
            "/a/b/y/z/c",
            "/a/x/b/b/c",
            "/a/b/c/b/c",
        ] {
            assert_eq!(decide(&rules, "a.com", "GET", p), Decision::Allow, "{p}");
        }
        for p in ["/a/c", "/b/c", "/a/b", "/a/b/c/d", "/x/a/b/c"] {
            assert!(is_deny(decide(&rules, "a.com", "GET", p)), "{p}");
        }
        let rules = [allow("a.com/**/**")];
        assert_eq!(decide(&rules, "a.com", "GET", "/"), Decision::Allow);
        assert_eq!(decide(&rules, "a.com", "GET", "/x/y"), Decision::Allow);
    }

    /// The path is the guest's, so matching must not backtrack: a long path
    /// against a rule with several `**` has to be decided promptly.
    #[test]
    fn a_long_path_against_many_double_stars_is_decided_promptly() {
        let (done, decided) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let rules = [deny("a.com/**/a/**/a/**/a/**/a/**/x")];
            let path = "/a".repeat(20_000);
            let _ = done.send(decide(&rules, "a.com", "GET", &path));
        });
        let decision = decided
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("matching a long path must not backtrack");
        assert_eq!(decision, Decision::Allow, "no rule path matches");
    }

    #[test]
    fn canonical_path_cannot_bypass_deny() {
        let rules = [deny("POST github.com/**/git-receive-pack")];
        assert!(is_deny(decide(
            &rules,
            "github.com",
            "POST",
            "/o/r/git%2Dreceive-pack"
        )));
        let rules = [deny("a.com/admin")];
        assert!(is_deny(decide(&rules, "a.com", "GET", "/x/../admin")));
        assert!(is_deny(decide(&rules, "a.com", "GET", "/x/%2e%2e/admin")));
    }

    #[test]
    fn canonicalization_forms() {
        let rules = [allow("a.com/a/b")];
        for p in [
            "//a//b",
            "/a/./b",
            "/a%2Fb",
            "/a/b/",
            "/../a/b",
            "/a/c/../b",
        ] {
            assert_eq!(decide(&rules, "a.com", "GET", p), Decision::Allow, "{p}");
        }
        // Invalid escapes stay literal; a valid %2F still splits the segment.
        let rules = [allow("a.com/x/*")];
        assert_eq!(decide(&rules, "a.com", "GET", "/x/100%"), Decision::Allow);
        assert_eq!(decide(&rules, "a.com", "GET", "/x/100%zz"), Decision::Allow);
        assert!(is_deny(decide(&rules, "a.com", "GET", "/x/a%2Fb")));
    }

    #[test]
    fn methods_are_case_insensitive() {
        let rules = [allow("get a.com")];
        assert_eq!(decide(&rules, "a.com", "GET", "/"), Decision::Allow);
        assert_eq!(decide(&rules, "a.com", "get", "/"), Decision::Allow);
        assert!(is_deny(decide(&rules, "a.com", "POST", "/")));
    }

    #[test]
    fn hosts_use_host_pattern() {
        let rules = [allow("GET *.github.com")];
        assert_eq!(
            decide(&rules, "api.github.com", "GET", "/"),
            Decision::Allow
        );
        assert_eq!(
            decide(&rules, "API.GitHub.com", "GET", "/"),
            Decision::Allow
        );
        assert_eq!(decide(&rules, "github.com", "GET", "/"), Decision::Unruled);
        assert!(rules_name_host(&rules, "api.github.com"));
        assert!(!rules_name_host(&rules, "github.com"));
        // A bare host is exact, not apex-plus-subdomains.
        let rules = [deny("github.com")];
        assert_eq!(
            decide(&rules, "api.github.com", "GET", "/"),
            Decision::Unruled
        );
        assert!(rules_name_host(&rules, "github.com"));
        assert!(!rules_name_host(&[], "github.com"));
    }

    #[test]
    fn parse_forms() {
        let r = allow("GET,HEAD a.com");
        assert_eq!(
            (r.hosts, r.methods, r.paths),
            (
                vec!["a.com".into()],
                vec!["GET".into(), "HEAD".into()],
                vec![]
            )
        );
        let r = allow("a.com/x/**");
        assert_eq!((r.methods, r.paths), (vec![], vec!["/x/**".into()]));
        let r = deny("POST a.com/x");
        assert_eq!(r.action, Action::Deny);
        assert_eq!(
            (r.methods, r.paths),
            (vec!["POST".into()], vec!["/x".into()])
        );
    }

    #[test]
    fn parse_errors() {
        for bad in [
            "",
            "/x",
            "GET /x",
            "GET,,HEAD a.com",
            ",GET a.com",
            "GET a.com x",
            "a.com/**/x y z",
        ] {
            assert!(RequestRule::parse(Action::Allow, bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn validate_refuses_what_parse_would() {
        assert_eq!(allow("GET a.com/x/**").validate(), Ok(()));
        let base = allow("a.com");
        for bad in [
            RequestRule {
                hosts: vec![],
                ..base.clone()
            },
            RequestRule {
                hosts: vec!["https://a.com".into()],
                ..base.clone()
            },
            RequestRule {
                paths: vec!["x/y".into()],
                ..base.clone()
            },
            RequestRule {
                methods: vec!["".into()],
                ..base.clone()
            },
            RequestRule {
                methods: vec!["G T".into()],
                ..base.clone()
            },
        ] {
            assert!(bad.validate().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn paths_that_could_never_match_are_refused() {
        for ok in ["a.com/v1/*/x", "a.com/v1/**", "a.com/*", "a.com/x.json"] {
            assert!(RequestRule::parse(Action::Deny, ok).is_ok(), "{ok}");
        }
        for (bad, why) in [
            ("a.com/v1/*.json", "whole segment"),
            ("a.com/v1/x*", "whole segment"),
            ("a.com/***", "whole segment"),
            ("a.com/admin%2Fusers", "must not contain %"),
            ("a.com/%61dmin", "must not contain %"),
        ] {
            let error = RequestRule::parse(Action::Deny, bad).unwrap_err();
            assert!(error.contains(why), "{bad}: {error}");
        }
    }

    #[test]
    fn json_shape() {
        let r: RequestRule =
            serde_json::from_str(r#"{"action":"deny","hosts":["a.com"],"methods":["POST"]}"#)
                .unwrap();
        assert_eq!(r.action, Action::Deny);
        assert!(r.paths.is_empty());
        assert!(
            serde_json::from_str::<RequestRule>(r#"{"action":"allow","hosts":[],"x":1}"#).is_err()
        );
    }
}
