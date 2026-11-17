//! Matching for persisted network host entries.
//!
//! Bare entries retain the original exact-or-subdomain behavior. New strict
//! entries use `=host` for exact matching or `*.host` for subdomains only.
//! The `=` prefix is internal; users write `--allow-host-pattern host`.
//! Host syntax follows RFC 1035 §§2.3.1, 2.3.4, 3.1 and RFC 1123 §2.1.

/// Encode an opt-in host pattern for storage alongside legacy entries.
pub fn encode_strict(pattern: &str) -> Result<String, String> {
    // A single trailing dot denotes the DNS root; a second dot is an empty label.
    let pattern = pattern.strip_suffix('.').unwrap_or(pattern);
    // Only a leading `*.` is syntax; everything after it must be a hostname.
    let (host, wildcard) = match pattern.strip_prefix("*.") {
        Some(host) => (host, true),
        None => (pattern, false),
    };
    // A pattern must name a host; `*.` alone has no DNS suffix to constrain it.
    let empty_host = host.is_empty();
    // RFC 1035 §§2.3.4/3.1: 255 wire octets permit 253 dotted ASCII bytes without the root dot.
    let name_too_long = host.len() > 253;
    // Only the leading `*.` has wildcard meaning; embedded or repeated stars are unsupported.
    let extra_wildcard = host.contains('*');
    // IP literals belong in CIDR policy; a bare pattern must be a DNS hostname.
    let ip_literal = !wildcard && host.parse::<std::net::IpAddr>().is_ok();
    let invalid_label = host.split('.').any(|label| {
        // Empty labels represent consecutive dots, which are not hostname separators.
        let empty = label.is_empty();
        // RFC 1035 §3.1 limits each DNS label to 63 octets.
        let too_long = label.len() > 63;
        // RFC 1035's preferred host syntax (with RFC 1123's leading-digit update) forbids edge hyphens.
        let edge_hyphen = label.starts_with('-') || label.ends_with('-');
        // Limit host policies to ASCII letters, digits, and hyphens rather than arbitrary DNS owner names.
        let non_hostname_character = !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
        empty || too_long || edge_hyphen || non_hostname_character
    });
    if empty_host || name_too_long || extra_wildcard || ip_literal || invalid_label {
        return Err(format!(
            "invalid host pattern {pattern:?}: use an exact DNS hostname or *.domain"
        ));
    }
    Ok(if wildcard {
        format!("*.{}", host.to_ascii_lowercase())
    } else {
        format!("={}", host.to_ascii_lowercase())
    })
}

/// Match a hostname against a legacy or opt-in network entry.
pub fn matches(host: &str, entry: &str) -> bool {
    // DNS comparisons ignore ASCII case and a terminal root dot; keep legacy normalization.
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let entry = entry.trim_end_matches('.').to_ascii_lowercase();
    // `=` marks opt-in exact entries; an empty stored entry must not match a name.
    if let Some(exact) = entry.strip_prefix('=') {
        return !exact.is_empty() && host == exact;
    }
    // `*.` requires a dot-bounded, nonempty prefix, so it excludes the apex.
    if let Some(suffix) = entry.strip_prefix("*.") {
        return !suffix.is_empty()
            && host
                .strip_suffix(suffix)
                .is_some_and(|prefix| prefix.ends_with('.') && prefix.len() > 1);
    }
    // Unmarked persisted entries retain the old apex-plus-subdomains behavior.
    !entry.is_empty()
        && (host == entry
            || host
                .strip_suffix(&entry)
                .is_some_and(|prefix| prefix.ends_with('.')))
}

/// Get the exact hostname to resolve into static CIDRs, if one exists.
/// Wildcard entries learn their addresses as concrete DNS queries succeed.
pub fn static_resolution_host(entry: &str) -> Option<&str> {
    if entry.starts_with("*.") {
        None
    } else {
        Some(entry.strip_prefix('=').unwrap_or(entry))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_and_new_entries_have_distinct_semantics() {
        assert!(matches("api.example.com", "example.com"));
        assert!(matches("example.com", "example.com"));
        let exact = encode_strict("Example.COM").unwrap();
        assert_eq!(exact, "=example.com");
        assert_eq!(encode_strict("Example.COM.").unwrap(), exact);
        assert!(matches("EXAMPLE.COM.", &exact));
        assert!(!matches("api.example.com", &exact));
        let wildcard = encode_strict("*.example.com").unwrap();
        assert!(matches("api.example.com", &wildcard));
        assert!(matches("a.b.example.com", &wildcard));
        assert!(!matches("example.com", &wildcard));
        assert!(!matches("notexample.com", &wildcard));
        assert!(!matches("example.com.evil.test", &wildcard));
    }

    #[test]
    fn rejects_invalid_patterns() {
        for pattern in [
            "",
            "*",
            "*.",
            "*.*.example.com",
            "foo*.example.com",
            "https://example.com",
            "example.com:443",
            "example.com..",
            "1.2.3.4",
        ] {
            assert!(encode_strict(pattern).is_err(), "{pattern}");
        }
    }

    #[test]
    fn enforces_dns_name_and_label_size_limits() {
        let longest_name = [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61),
        ]
        .join(".");
        assert_eq!(longest_name.len(), 253);
        assert!(encode_strict(&longest_name).is_ok());
        assert!(encode_strict(&format!("{longest_name}d")).is_err());
        assert!(encode_strict(&"a".repeat(64)).is_err());
    }
}
