//! Shared utility functions.

use std::time::{SystemTime, UNIX_EPOCH};

// Re-export retry utilities from the protocol crate for convenience.
// This provides a single source of truth for retry logic across the codebase.
pub use smolvm_protocol::retry::{
    is_transient_io_error, is_transient_network_error, retry_with_backoff, RetryConfig,
};

/// Workload marker set when smolvm's best-effort CUDA graph policy is enabled.
pub const CUDA_AUTO_GRAPH_ENV: &str = "SMOLVM_CUDA_AUTO_GRAPH";

/// PyTorch Inductor switch for CUDA graphs in compatible compiled regions.
pub const TORCHINDUCTOR_CUDAGRAPHS_ENV: &str = "TORCHINDUCTOR_CUDAGRAPHS";

/// Generate a short random ID for auto-naming machines.
///
/// Produces an 8-character hex string (e.g., "a1b2c3d4") from 4 bytes
/// of OS entropy. Falls back to time+pid if /dev/urandom is unavailable.
pub fn generate_short_id() -> String {
    let mut buf = [0u8; 4];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| {
            use std::io::Read;
            f.read_exact(&mut buf)
        })
        .is_ok()
    {
        return format!("{:08x}", u32::from_le_bytes(buf));
    }
    // Fallback: time + pid (less random but functional)
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:08x}", (nanos as u32) ^ std::process::id())
}

/// Generate an auto machine name (e.g., "vm-a1b2c3d4").
pub fn generate_machine_name() -> String {
    format!("vm-{}", generate_short_id())
}

/// Get current timestamp as seconds since Unix epoch.
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Get the filename of libkrunfw dynamic lib
pub fn libkrunfw_filename() -> &'static str {
    #[cfg(target_os = "macos")]
    let lib_name = "libkrunfw.5.dylib";
    #[cfg(target_os = "linux")]
    let lib_name = "libkrunfw.so.5";
    #[cfg(target_os = "windows")]
    let lib_name = "libkrunfw.dll";
    lib_name
}

/// Get the filename of the libkrun dynamic lib
pub fn libkrun_filename() -> &'static str {
    #[cfg(target_os = "macos")]
    let lib_name = "libkrun.dylib";
    #[cfg(target_os = "linux")]
    let lib_name = "libkrun.so";
    #[cfg(target_os = "windows")]
    let lib_name = "krun.dll";
    lib_name
}

/// Parse a single environment variable specification.
///
/// - `KEY=VALUE` → `Some((KEY, VALUE))`.
/// - `KEY` (no `=`) → forwards the host's current value for `KEY` (Docker
///   `-e KEY` semantics); `None` if the host variable is unset.
/// - empty key (`=VALUE`) or empty spec → `None`.
pub fn parse_env_spec(spec: &str) -> Option<(String, String)> {
    match spec.split_once('=') {
        Some((key, value)) => {
            if key.is_empty() {
                None
            } else {
                Some((key.to_string(), value.to_string()))
            }
        }
        None => {
            if spec.is_empty() {
                None
            } else {
                // Key-only form: forward the value from the host environment.
                std::env::var(spec).ok().map(|v| (spec.to_string(), v))
            }
        }
    }
}

/// Parse `KEY=VALUE` entries that arrived in an API request.
///
/// Unlike [`parse_env_list`], every entry must name its value: a bare `KEY`
/// is an error, never a copy of this process's own variable (the server's
/// environment is not the caller's to read), and a malformed entry is an
/// error rather than silently dropped. Errors name the entry by position so a
/// value is never echoed back.
pub fn parse_request_env_list(env: &[String]) -> Result<Vec<(String, String)>, String> {
    env.iter()
        .enumerate()
        .map(|(index, spec)| match spec.split_once('=') {
            Some((key, value)) if !key.is_empty() => Ok((key.to_string(), value.to_string())),
            _ => Err(format!(
                "env entry {index} must be KEY=VALUE with a non-empty KEY"
            )),
        })
        .collect()
}

/// Parse a list of `KEY=VALUE` strings into `(key, value)` tuples.
///
/// Silently skips malformed entries (empty key), and forwards a bare `KEY`
/// from this process's environment: for the CLI's own `-e`, never API input.
pub fn parse_env_list(env_args: &[String]) -> Vec<(String, String)> {
    env_args.iter().filter_map(|e| parse_env_spec(e)).collect()
}

fn unescape_double_quotes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('\\') => out.push('\\'),
                Some('"') => out.push('"'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn strip_inline_comment(s: &str) -> &str {
    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'#' && i > 0 && (bytes[i - 1] == b' ' || bytes[i - 1] == b'\t') {
            return s[..i].trim_end();
        }
    }
    s.trim_end()
}

/// Parse the contents of an environment file into `(key, value)` pairs.
///
/// Follows standard dotenv conventions (Docker / 12-factor):
/// - Blank lines and comment lines (starting with `#`) are ignored.
/// - An optional leading `export ` prefix is stripped (e.g. `export KEY=VALUE`).
/// - Splits on the first `=`:
///   - `KEY=VALUE`: `KEY` is trimmed of whitespace.
///     - Single-quoted values (`'...'`): contents are taken literally.
///     - Double-quoted values (`"..."`): unescapes `\n`, `\r`, `\t`, `\\`, and `\"`.
///     - Unquoted values: whitespace is trimmed, and trailing unquoted comments
///       (preceded by whitespace, e.g. `foo # comment`) are stripped.
///   - `KEY` (no `=`): forwards the current value from the host environment
///     (matching Docker's `--env-file` and [`parse_env_spec`]); skipped if unset.
/// - Duplicate keys keep the last occurrence.
pub fn parse_env_file_contents(contents: &str) -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String)> = Vec::new();

    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let line = line.strip_prefix("export ").unwrap_or(line).trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some((raw_key, raw_val)) = line.split_once('=') {
            let key = raw_key.trim();
            if key.is_empty() {
                continue;
            }
            let val = raw_val.trim();
            let value = if val.starts_with('"') && val.ends_with('"') && val.len() >= 2 {
                unescape_double_quotes(&val[1..val.len() - 1])
            } else if val.starts_with('\'') && val.ends_with('\'') && val.len() >= 2 {
                val[1..val.len() - 1].to_string()
            } else {
                strip_inline_comment(val).trim().to_string()
            };

            pairs.retain(|(k, _)| k != key);
            pairs.push((key.to_string(), value));
        } else {
            // Key-only form: resolve from host environment
            let key = line.trim();
            if !key.is_empty() {
                if let Ok(host_val) = std::env::var(key) {
                    pairs.retain(|(k, _)| k != key);
                    pairs.push((key.to_string(), host_val));
                }
            }
        }
    }

    pairs
}

/// Read and parse an environment file at `path`.
pub fn parse_env_file(path: impl AsRef<std::path::Path>) -> crate::Result<Vec<(String, String)>> {
    let path = path.as_ref();
    let contents = std::fs::read_to_string(path).map_err(|e| {
        crate::Error::config(
            "--env-file",
            format!("failed to read '{}': {e}", path.display()),
        )
    })?;
    Ok(parse_env_file_contents(&contents))
}

/// Read and merge multiple environment files in order.
/// Later files override earlier files for matching keys.
pub fn load_env_files(
    paths: &[impl AsRef<std::path::Path>],
) -> crate::Result<Vec<(String, String)>> {
    let mut merged: Vec<(String, String)> = Vec::new();
    for path in paths {
        let entries = parse_env_file(path)?;
        layer_env(&mut merged, entries);
    }
    Ok(merged)
}

/// Enable best-effort CUDA graphs in a parsed workload environment.
///
/// Existing values are replaced so an explicit auto-graph request has one
/// canonical result. Frameworks remain responsible for deciding which regions
/// are safe to capture.
pub fn enable_cuda_auto_graph_env(env: &mut Vec<(String, String)>) {
    for name in [CUDA_AUTO_GRAPH_ENV, TORCHINDUCTOR_CUDAGRAPHS_ENV] {
        env.retain(|(existing, _)| existing != name);
        env.push((name.to_string(), "1".to_string()));
    }
}

/// Enable best-effort CUDA graphs in `KEY=VALUE` workload specifications.
pub fn enable_cuda_auto_graph_env_specs(env: &mut Vec<String>) {
    for name in [CUDA_AUTO_GRAPH_ENV, TORCHINDUCTOR_CUDAGRAPHS_ENV] {
        env.retain(|spec| spec.split_once('=').map_or(spec.as_str(), |(key, _)| key) != name);
        env.push(format!("{name}=1"));
    }
}

/// Parse a byte size like `16GiB`, `16G`, `512M`, or a plain byte count
/// (`17179869184`). Suffixes are binary (1K = 1024); `K/M/G/T`, optionally with
/// a trailing `i` and/or `B`, are accepted case-insensitively.
pub fn parse_size_bytes(s: &str) -> Result<u64, String> {
    let t = s.trim();
    if t.is_empty() {
        return Err("size must not be empty".to_string());
    }
    let split = t
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(t.len());
    let (num, unit) = t.split_at(split);
    let value: f64 = num
        .parse()
        .map_err(|_| format!("'{s}' is not a valid size (expected a number, optional K/M/G/T)"))?;
    let mult: u64 = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "ki" | "kib" | "kb" => 1 << 10,
        "m" | "mi" | "mib" | "mb" => 1 << 20,
        "g" | "gi" | "gib" | "gb" => 1 << 30,
        "t" | "ti" | "tib" | "tb" => 1u64 << 40,
        other => {
            return Err(format!(
                "invalid size unit '{other}' in '{s}' (use K, M, G, or T)"
            ))
        }
    };
    let bytes = (value * mult as f64) as u64;
    if bytes == 0 {
        return Err(format!("size '{s}' must be greater than zero"));
    }
    Ok(bytes)
}

/// Parse repeated `--label key=value` pairs into machine labels.
///
/// Lives in the library rather than a front end because both CLIs and SDK
/// callers set labels: two parsers would eventually disagree about where the key
/// ends, and a label the writer and the reader parse differently is worse than
/// no label at all.
///
/// Split on the FIRST `=` only, so values may contain `=` (base64, query
/// strings). An empty key is rejected: it would be unaddressable, and silently
/// keeping it would corrupt `machine ls --json` for the caller reading it back.
pub fn parse_labels(raw: &[String]) -> crate::Result<std::collections::BTreeMap<String, String>> {
    let mut labels = std::collections::BTreeMap::new();
    for entry in raw {
        let Some((key, value)) = entry.split_once('=') else {
            return Err(crate::Error::config(
                "--label",
                format!("expected KEY=VALUE, got '{entry}'"),
            ));
        };
        if key.is_empty() {
            return Err(crate::Error::config(
                "--label",
                format!("label key cannot be empty (in '{entry}')"),
            ));
        }
        labels.insert(key.to_string(), value.to_string());
    }
    Ok(labels)
}

#[cfg(test)]
mod tests {
    /// API env entries must carry their value: a bare name must never pull the
    /// server's own variable into a caller's machine, and a malformed entry is
    /// refused rather than dropped.
    #[test]
    fn request_env_needs_explicit_values_and_never_reads_the_server_env() {
        std::env::set_var("SMOLVM_TEST_SERVER_ONLY", "server-secret");
        let env = |specs: &[&str]| {
            super::parse_request_env_list(&specs.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        };
        assert_eq!(
            env(&["A=1", "B=x=y", "C="]).unwrap(),
            [
                ("A".into(), "1".into()),
                ("B".into(), "x=y".into()),
                ("C".into(), String::new())
            ]
        );
        let bare = env(&["A=1", "SMOLVM_TEST_SERVER_ONLY"]).unwrap_err();
        assert!(bare.contains("entry 1"), "{bare}");
        assert!(!bare.contains("server-secret"));
        assert!(env(&["=secret"]).unwrap_err().contains("entry 0"));
        assert!(!env(&["=secret"]).unwrap_err().contains("secret"));
        assert!(env(&[""]).is_err());
        // The CLI keeps forwarding a bare name from its own shell.
        assert_eq!(
            super::parse_env_list(&["SMOLVM_TEST_SERVER_ONLY".to_string()]),
            [(
                "SMOLVM_TEST_SERVER_ONLY".to_string(),
                "server-secret".to_string()
            )]
        );
    }

    #[test]
    fn parses_labels_and_keeps_values_containing_equals() {
        let labels = super::parse_labels(&[
            "owner=exo".to_string(),
            // Values are opaque to smolvm, so `=` inside one must survive.
            "token=abc=def==".to_string(),
            "empty=".to_string(),
        ])
        .expect("valid labels");
        assert_eq!(labels.get("owner").map(String::as_str), Some("exo"));
        assert_eq!(labels.get("token").map(String::as_str), Some("abc=def=="));
        assert_eq!(labels.get("empty").map(String::as_str), Some(""));
    }

    #[test]
    fn rejects_labels_that_could_not_be_read_back() {
        // No separator: treating this as a valueless key would hand the caller
        // back something they never wrote.
        assert!(super::parse_labels(&["notakeyvalue".to_string()]).is_err());
        // Empty key is unaddressable.
        assert!(super::parse_labels(&["=value".to_string()]).is_err());
    }

    #[test]
    fn later_label_wins_for_a_repeated_key() {
        let labels = super::parse_labels(&["k=first".to_string(), "k=second".to_string()])
            .expect("valid labels");
        assert_eq!(labels.get("k").map(String::as_str), Some("second"));
    }

    use super::*;
    use std::collections::HashSet;

    #[test]
    fn parse_env_spec_key_value() {
        assert_eq!(
            parse_env_spec("FOO=bar"),
            Some(("FOO".to_string(), "bar".to_string()))
        );
        // Empty value is allowed.
        assert_eq!(
            parse_env_spec("FOO="),
            Some(("FOO".to_string(), String::new()))
        );
        // Empty key is rejected.
        assert_eq!(parse_env_spec("=bar"), None);
        assert_eq!(parse_env_spec(""), None);
    }

    #[test]
    fn auto_graph_env_replaces_conflicting_values() {
        let mut env = vec![
            ("KEEP".to_string(), "yes".to_string()),
            (TORCHINDUCTOR_CUDAGRAPHS_ENV.to_string(), "0".to_string()),
            (CUDA_AUTO_GRAPH_ENV.to_string(), "old".to_string()),
        ];

        enable_cuda_auto_graph_env(&mut env);

        assert_eq!(
            env,
            vec![
                ("KEEP".to_string(), "yes".to_string()),
                (CUDA_AUTO_GRAPH_ENV.to_string(), "1".to_string()),
                (TORCHINDUCTOR_CUDAGRAPHS_ENV.to_string(), "1".to_string()),
            ]
        );
    }

    #[test]
    fn auto_graph_env_specs_replaces_conflicting_values() {
        let mut env = vec![
            "KEEP=yes".to_string(),
            "TORCHINDUCTOR_CUDAGRAPHS=0".to_string(),
            "SMOLVM_CUDA_AUTO_GRAPH".to_string(),
        ];

        enable_cuda_auto_graph_env_specs(&mut env);

        assert_eq!(
            env,
            vec![
                "KEEP=yes".to_string(),
                "SMOLVM_CUDA_AUTO_GRAPH=1".to_string(),
                "TORCHINDUCTOR_CUDAGRAPHS=1".to_string(),
            ]
        );
    }

    #[test]
    fn parse_env_spec_key_only_forwards_host_value() {
        let key = "SMOLVM_TEST_ENV_FWD_XYZ";
        std::env::set_var(key, "host_value");
        assert_eq!(
            parse_env_spec(key),
            Some((key.to_string(), "host_value".to_string()))
        );
        std::env::remove_var(key);
        // Unset host var → skipped.
        assert_eq!(parse_env_spec(key), None);
    }

    #[test]
    fn test_generate_ids() {
        // Generate 100 IDs and validate all of them
        let ids: Vec<String> = (0..100).map(|_| generate_short_id()).collect();

        for id in &ids {
            assert_eq!(id.len(), 8, "should be 8 hex chars: {id}");
            assert!(id.chars().all(|c| c.is_ascii_hexdigit()), "not hex: {id}");
        }

        // All unique
        let unique: HashSet<&String> = ids.iter().collect();
        assert_eq!(unique.len(), 100, "100 IDs should all be unique");

        // Machine name wraps the ID correctly
        let name = generate_machine_name();
        assert!(name.starts_with("vm-"), "prefix: {name}");
        assert_eq!(name.len(), 11, "length: {name}");
        assert!(name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));

        // Two names differ
        assert_ne!(generate_machine_name(), generate_machine_name());
    }
}

/// Add `layer` over `env`: a variable it sets replaces the earlier value
/// rather than appearing twice.
pub fn layer_env(env: &mut Vec<(String, String)>, layer: Vec<(String, String)>) {
    for (name, value) in layer {
        env.retain(|(existing, _)| existing != &name);
        env.push((name, value));
    }
}

#[cfg(test)]
mod layer_env_tests {
    use super::layer_env;

    #[test]
    fn a_later_layer_replaces_a_variable_instead_of_repeating_it() {
        let mut env = vec![
            ("A".to_string(), "1".to_string()),
            ("B".to_string(), "2".to_string()),
        ];
        layer_env(
            &mut env,
            vec![
                ("B".to_string(), "3".to_string()),
                ("C".to_string(), "4".to_string()),
            ],
        );
        assert_eq!(
            env,
            vec![
                ("A".to_string(), "1".to_string()),
                ("B".to_string(), "3".to_string()),
                ("C".to_string(), "4".to_string()),
            ]
        );
    }
}

#[cfg(test)]
mod env_file_tests {
    use super::*;

    #[test]
    fn parses_dotenv_contents_with_quotes_comments_and_exports() {
        let text = r#"
# Comment line
FOO=bar
export BAZ=qux
EMPTY=
SPACED = hello world 
SINGLE='literal $VAR # not comment'
DOUBLE="quoted with \"quotes\", \n newline and \t tab"
INLINE_COMMENT=normal_value # this is stripped
URL=https://example.com/page#anchor
export OVERRIDE=initial
OVERRIDE=final
"#;
        let parsed = parse_env_file_contents(text);
        let map: std::collections::BTreeMap<_, _> = parsed.into_iter().collect();

        assert_eq!(map.get("FOO").map(String::as_str), Some("bar"));
        assert_eq!(map.get("BAZ").map(String::as_str), Some("qux"));
        assert_eq!(map.get("EMPTY").map(String::as_str), Some(""));
        assert_eq!(map.get("SPACED").map(String::as_str), Some("hello world"));
        assert_eq!(
            map.get("SINGLE").map(String::as_str),
            Some("literal $VAR # not comment")
        );
        assert_eq!(
            map.get("DOUBLE").map(String::as_str),
            Some("quoted with \"quotes\", \n newline and \t tab")
        );
        assert_eq!(
            map.get("INLINE_COMMENT").map(String::as_str),
            Some("normal_value")
        );
        assert_eq!(
            map.get("URL").map(String::as_str),
            Some("https://example.com/page#anchor")
        );
        assert_eq!(map.get("OVERRIDE").map(String::as_str), Some("final"));
    }

    #[test]
    fn forwards_bare_keys_from_host_environment() {
        let key = "SMOLVM_TEST_DOTENV_KEY";
        std::env::set_var(key, "host_secret");
        let text = format!("{key}\nUNSET_HOST_VAR_XYZ\nOTHER=123");
        let parsed = parse_env_file_contents(&text);
        std::env::remove_var(key);

        let map: std::collections::BTreeMap<_, _> = parsed.into_iter().collect();
        assert_eq!(map.get(key).map(String::as_str), Some("host_secret"));
        assert_eq!(map.get("UNSET_HOST_VAR_XYZ"), None);
        assert_eq!(map.get("OTHER").map(String::as_str), Some("123"));
    }

    #[test]
    fn load_env_files_merges_in_order() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file1 = temp_dir.path().join("base.env");
        let file2 = temp_dir.path().join("override.env");

        std::fs::write(&file1, "A=1\nB=2\n").unwrap();
        std::fs::write(&file2, "B=override\nC=3\n").unwrap();

        let merged = load_env_files(&[&file1, &file2]).unwrap();
        assert_eq!(
            merged,
            vec![
                ("A".to_string(), "1".to_string()),
                ("B".to_string(), "override".to_string()),
                ("C".to_string(), "3".to_string()),
            ]
        );

        // Missing file returns an error
        let missing = temp_dir.path().join("missing.env");
        assert!(load_env_files(&[&file1, &missing]).is_err());
    }
}
