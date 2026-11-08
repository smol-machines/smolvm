//! Host-side wiring for `smolvm docker`: the stable socket path, the `smol`
//! docker context, Testcontainers' properties file, and a readiness probe.
//!
//! Every function here takes the directories it touches as arguments, so the
//! unit tests run against a temporary directory instead of the user's home.

use std::io::Write;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::time::Duration;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Name of the docker context `smolvm docker` creates and selects.
pub const CONTEXT_NAME: &str = "smol";

/// Description stored on the context, shown by `docker context ls`.
const CONTEXT_DESCRIPTION: &str = "smolvm Docker machine";

/// Directories Homebrew's `docker-compose` and `docker-buildx` formulae install
/// their CLI plugins into. The docker CLI only finds them once
/// `cliPluginsExtraDirs` names the directory, which the formulae leave to the
/// user.
const PLUGIN_DIRS: [&str; 2] = [
    "/opt/homebrew/lib/docker/cli-plugins",
    "/usr/local/lib/docker/cli-plugins",
];

/// `unix://` URL of a socket path.
pub fn socket_url(socket: &Path) -> String {
    format!("unix://{}", socket.display())
}

/// Point `link` at `target`, replacing an older link. Anything at `link` that
/// is not a symlink is someone else's and is left alone.
#[cfg(unix)]
pub fn link_socket(link: &Path, target: &Path) -> std::io::Result<()> {
    if let Some(dir) = link.parent() {
        std::fs::create_dir_all(dir)?;
    }
    match std::fs::symlink_metadata(link) {
        Ok(meta) if meta.file_type().is_symlink() => {
            if std::fs::read_link(link)? == target {
                return Ok(());
            }
            std::fs::remove_file(link)?;
        }
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "{} exists and is not a link smolvm made; move it away first",
                    link.display()
                ),
            ))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    std::os::unix::fs::symlink(target, link)
}

/// Unix sockets and symlinks for them: not on this host.
#[cfg(not(unix))]
pub fn link_socket(_link: &Path, _target: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "the Docker socket link needs a Unix host",
    ))
}

/// Remove `link` if it is a symlink pointing at `target`.
pub fn unlink_socket(link: &Path, target: &Path) -> std::io::Result<()> {
    match std::fs::read_link(link) {
        Ok(current) if current == target => std::fs::remove_file(link),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        // Not a symlink (EINVAL): not ours.
        Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => Ok(()),
        Err(e) => Err(e),
    }
}

/// The docker CLI's configuration directory: `$DOCKER_CONFIG`, else
/// `~/.docker`.
pub fn docker_config_dir(home: &Path, docker_config_env: Option<&str>) -> PathBuf {
    match docker_config_env.filter(|value| !value.is_empty()) {
        Some(dir) => PathBuf::from(dir),
        None => home.join(".docker"),
    }
}

/// Where the docker CLI keeps a context's metadata: a directory named by the
/// SHA-256 of the context name.
fn context_meta_dir(config_dir: &Path, name: &str) -> PathBuf {
    let digest = Sha256::digest(name.as_bytes());
    config_dir
        .join("contexts")
        .join("meta")
        .join(hex::encode(digest))
}

/// What happened to the docker CLI configuration.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ContextOutcome {
    /// The context selected before, when it was not ours.
    pub previous: Option<String>,
    /// Plugin directory added to `cliPluginsExtraDirs`.
    pub plugin_dir_added: Option<String>,
}

/// Create (or update) the `smol` context for `socket` and make it the current
/// one, exactly as `docker context create` + `docker context use` would. The
/// docker CLI does not have to be installed yet. Homebrew's compose and buildx
/// plugin directory is added to `cliPluginsExtraDirs` when it exists and the
/// configuration names none.
pub fn install_context(
    config_dir: &Path,
    socket: &Path,
    plugin_dirs: &[&Path],
) -> std::io::Result<ContextOutcome> {
    let meta_dir = context_meta_dir(config_dir, CONTEXT_NAME);
    std::fs::create_dir_all(&meta_dir)?;
    let meta = serde_json::json!({
        "Name": CONTEXT_NAME,
        "Metadata": { "Description": CONTEXT_DESCRIPTION },
        "Endpoints": {
            "docker": { "Host": socket_url(socket), "SkipTLSVerify": false }
        }
    });
    write_json(&meta_dir.join("meta.json"), &meta)?;

    let config_path = config_dir.join("config.json");
    let mut config = read_json_object(&config_path)?;
    let mut outcome = ContextOutcome {
        previous: config
            .get("currentContext")
            .and_then(Value::as_str)
            .filter(|name| *name != CONTEXT_NAME && *name != "default")
            .map(str::to_string),
        ..ContextOutcome::default()
    };
    config.insert(
        "currentContext".to_string(),
        Value::String(CONTEXT_NAME.to_string()),
    );
    if !config.contains_key("cliPluginsExtraDirs") {
        if let Some(dir) = plugin_dirs.iter().find(|dir| dir.is_dir()) {
            let dir = dir.display().to_string();
            config.insert(
                "cliPluginsExtraDirs".to_string(),
                Value::Array(vec![Value::String(dir.clone())]),
            );
            outcome.plugin_dir_added = Some(dir);
        }
    }
    write_json(&config_path, &Value::Object(config))?;
    Ok(outcome)
}

/// The Homebrew plugin directories that exist on this host, in preference
/// order.
pub fn homebrew_plugin_dirs() -> Vec<&'static Path> {
    PLUGIN_DIRS.iter().map(Path::new).collect()
}

/// Remove the `smol` context if it still points at `socket`, and stop
/// selecting it.
pub fn remove_context(config_dir: &Path, socket: &Path) -> std::io::Result<()> {
    let meta_dir = context_meta_dir(config_dir, CONTEXT_NAME);
    let meta_path = meta_dir.join("meta.json");
    if let Ok(text) = std::fs::read_to_string(&meta_path) {
        let host = serde_json::from_str::<Value>(&text).ok().and_then(|meta| {
            meta.pointer("/Endpoints/docker/Host")
                .and_then(Value::as_str)
                .map(str::to_string)
        });
        if host.as_deref() == Some(socket_url(socket).as_str()) {
            std::fs::remove_dir_all(&meta_dir)?;
        }
    }
    let config_path = config_dir.join("config.json");
    if config_path.exists() {
        let mut config = read_json_object(&config_path)?;
        if config.get("currentContext").and_then(Value::as_str) == Some(CONTEXT_NAME) {
            config.remove("currentContext");
            write_json(&config_path, &Value::Object(config))?;
        }
    }
    Ok(())
}

/// The context the docker CLI uses now, from `config.json`.
pub fn current_context(config_dir: &Path) -> Option<String> {
    let text = std::fs::read_to_string(config_dir.join("config.json")).ok()?;
    serde_json::from_str::<Value>(&text)
        .ok()?
        .get("currentContext")?
        .as_str()
        .map(str::to_string)
}

fn read_json_object(path: &Path) -> std::io::Result<Map<String, Value>> {
    match std::fs::read_to_string(path) {
        Ok(text) if text.trim().is_empty() => Ok(Map::new()),
        Ok(text) => match serde_json::from_str::<Value>(&text) {
            Ok(Value::Object(map)) => Ok(map),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{} is not a JSON object; fix or remove it", path.display()),
            )),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Map::new()),
        Err(e) => Err(e),
    }
}

/// Write `value` to `path` through a temporary file and a rename, keeping the
/// mode of the file it replaces (0600 for a new one, as the docker CLI does).
fn write_json(path: &Path, value: &Value) -> std::io::Result<()> {
    let mut text = serde_json::to_string_pretty(value).map_err(std::io::Error::other)?;
    text.push('\n');
    write_atomically(path, text.as_bytes())
}

fn write_atomically(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir)?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    tmp.write_all(bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .map(|meta| meta.permissions().mode() & 0o777)
            .unwrap_or(0o600);
        tmp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(mode))?;
    }
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

/// What `ensure_testcontainers_host` did.
#[derive(Debug, PartialEq, Eq)]
pub enum PropertiesOutcome {
    /// `docker.host` was written.
    Written,
    /// It already named this socket.
    Unchanged,
    /// It names another engine and was left alone.
    Other(String),
}

/// Testcontainers reads `docker.host` from `~/.testcontainers.properties`
/// before it probes the default socket, so naming the stable socket there lets
/// a test suite find the engine with no `DOCKER_HOST`. An existing
/// `docker.host` for another engine is left alone.
pub fn ensure_testcontainers_host(
    properties: &Path,
    socket: &Path,
) -> std::io::Result<PropertiesOutcome> {
    let url = socket_url(socket);
    let text = match std::fs::read_to_string(properties) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e),
    };
    if let Some(current) = property(&text, "docker.host") {
        return Ok(if current == url {
            PropertiesOutcome::Unchanged
        } else {
            PropertiesOutcome::Other(current)
        });
    }
    let mut updated = text;
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(&format!("docker.host={url}\n"));
    write_atomically(properties, updated.as_bytes())?;
    Ok(PropertiesOutcome::Written)
}

/// Remove the `docker.host` line if it names `socket`; delete the file when
/// nothing else is left in it.
pub fn remove_testcontainers_host(properties: &Path, socket: &Path) -> std::io::Result<()> {
    let text = match std::fs::read_to_string(properties) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    let url = socket_url(socket);
    let kept: Vec<&str> = text
        .lines()
        .filter(|line| parse_property(line) != Some(("docker.host", url.as_str())))
        .collect();
    if kept.len() == text.lines().count() {
        return Ok(());
    }
    if kept.iter().all(|line| line.trim().is_empty()) {
        return std::fs::remove_file(properties);
    }
    let mut updated = kept.join("\n");
    updated.push('\n');
    write_atomically(properties, updated.as_bytes())
}

fn property(text: &str, key: &str) -> Option<String> {
    text.lines()
        .filter_map(parse_property)
        .find(|(k, _)| *k == key)
        .map(|(_, value)| value.to_string())
}

/// `key=value` or `key: value` from one line of a Java properties file;
/// comments and blank lines give `None`.
fn parse_property(line: &str) -> Option<(&str, &str)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
        return None;
    }
    let split = line.find(['=', ':'])?;
    Some((line[..split].trim(), line[split + 1..].trim()))
}

/// Ask the engine behind `socket` for `path` with a plain HTTP/1.0 GET and
/// return the status code and body. One short exchange; nothing is pipelined.
#[cfg(unix)]
pub fn engine_get(socket: &Path, path: &str, timeout: Duration) -> std::io::Result<(u16, String)> {
    use std::io::Read;
    let mut stream = std::os::unix::net::UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    write!(stream, "GET {path} HTTP/1.0\r\nHost: docker\r\n\r\n")?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    parse_http_response(&response).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "the engine sent a malformed HTTP response",
        )
    })
}

#[cfg_attr(not(unix), allow(dead_code))]
fn parse_http_response(response: &[u8]) -> Option<(u16, String)> {
    let text = String::from_utf8_lossy(response);
    let (head, body) = text.split_once("\r\n\r\n")?;
    let status = head
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    Some((status, body.to_string()))
}

/// Whether the engine answers `/_ping` with `OK`.
#[cfg(unix)]
pub fn engine_ready(socket: &Path) -> bool {
    matches!(
        engine_get(socket, "/_ping", Duration::from_secs(3)),
        Ok((200, body)) if body.trim() == "OK"
    )
}

/// The engine's version string from `/version`.
#[cfg(unix)]
pub fn engine_version(socket: &Path) -> Option<String> {
    let (status, body) = engine_get(socket, "/version", Duration::from_secs(5)).ok()?;
    if status != 200 {
        return None;
    }
    serde_json::from_str::<Value>(&body)
        .ok()?
        .get("Version")?
        .as_str()
        .map(str::to_string)
}

/// Whether the engine answers: never on a host without Unix sockets.
#[cfg(not(unix))]
pub fn engine_ready(_socket: &Path) -> bool {
    false
}

/// The engine's version: unknown on a host without Unix sockets.
#[cfg(not(unix))]
pub fn engine_version(_socket: &Path) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_dir_is_the_sha256_of_the_name() {
        // The docker CLI's own layout: `docker context create smol` makes this
        // directory.
        let dir = context_meta_dir(Path::new("/c"), "smol");
        assert_eq!(
            dir,
            Path::new(
                "/c/contexts/meta/ec2b18d8ea944f24f342dfb1d6b12da709cb2d7344eec4d0bc7835d3e51621a7"
            )
        );
    }

    #[test]
    fn install_context_writes_meta_and_selects_it_keeping_other_keys() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("config.json"),
            r#"{"auths":{"ghcr.io":{}},"currentContext":"remote"}"#,
        )
        .unwrap();
        let socket = Path::new("/Users/me/.smolvm/run/docker.sock");
        let outcome = install_context(dir.path(), socket, &[]).unwrap();
        assert_eq!(outcome.previous.as_deref(), Some("remote"));
        assert_eq!(outcome.plugin_dir_added, None);

        let config: Value =
            serde_json::from_str(&std::fs::read_to_string(dir.path().join("config.json")).unwrap())
                .unwrap();
        assert_eq!(config["currentContext"], "smol");
        assert!(config["auths"]["ghcr.io"].is_object());
        let meta: Value = serde_json::from_str(
            &std::fs::read_to_string(context_meta_dir(dir.path(), "smol").join("meta.json"))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(meta["Name"], "smol");
        assert_eq!(
            meta["Endpoints"]["docker"]["Host"],
            "unix:///Users/me/.smolvm/run/docker.sock"
        );
        assert_eq!(current_context(dir.path()).as_deref(), Some("smol"));
    }

    #[test]
    fn install_context_adds_the_first_existing_plugin_dir_only_when_unset() {
        let dir = tempfile::tempdir().unwrap();
        let plugins = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing");
        let socket = Path::new("/s.sock");
        let outcome = install_context(dir.path(), socket, &[&missing, plugins.path()]).unwrap();
        assert_eq!(
            outcome.plugin_dir_added.as_deref(),
            Some(plugins.path().to_str().unwrap())
        );
        // A second run, or a user's own setting, is left as it is.
        let again = install_context(dir.path(), socket, &[plugins.path()]).unwrap();
        assert_eq!(again.plugin_dir_added, None);
        assert_eq!(again.previous, None);
    }

    #[cfg(unix)]
    #[test]
    fn new_config_json_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        install_context(dir.path(), Path::new("/s.sock"), &[]).unwrap();
        let mode = std::fs::metadata(dir.path().join("config.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn install_context_refuses_a_config_that_is_not_an_object() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("config.json"), "[1,2]").unwrap();
        let err = install_context(dir.path(), Path::new("/s.sock"), &[]).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn remove_context_only_removes_ours() {
        let dir = tempfile::tempdir().unwrap();
        let ours = Path::new("/a.sock");
        install_context(dir.path(), ours, &[]).unwrap();
        // Pointing somewhere else (the user re-created it): kept.
        remove_context(dir.path(), Path::new("/b.sock")).unwrap();
        assert!(context_meta_dir(dir.path(), "smol").exists());
        assert_eq!(current_context(dir.path()), None);
        install_context(dir.path(), ours, &[]).unwrap();
        remove_context(dir.path(), ours).unwrap();
        assert!(!context_meta_dir(dir.path(), "smol").exists());
        assert_eq!(current_context(dir.path()), None);
    }

    #[test]
    fn docker_config_env_wins_over_home() {
        let home = Path::new("/home/me");
        assert_eq!(
            docker_config_dir(home, None),
            PathBuf::from("/home/me/.docker")
        );
        assert_eq!(
            docker_config_dir(home, Some("")),
            PathBuf::from("/home/me/.docker")
        );
        assert_eq!(
            docker_config_dir(home, Some("/tmp/dc")),
            PathBuf::from("/tmp/dc")
        );
    }

    #[test]
    fn testcontainers_properties_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(".testcontainers.properties");
        let socket = Path::new("/Users/me/.smolvm/run/docker.sock");
        assert_eq!(
            ensure_testcontainers_host(&file, socket).unwrap(),
            PropertiesOutcome::Written
        );
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "docker.host=unix:///Users/me/.smolvm/run/docker.sock\n"
        );
        assert_eq!(
            ensure_testcontainers_host(&file, socket).unwrap(),
            PropertiesOutcome::Unchanged
        );
        remove_testcontainers_host(&file, socket).unwrap();
        assert!(!file.exists(), "a file holding only our line is removed");
    }

    #[test]
    fn testcontainers_properties_keep_other_settings() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(".testcontainers.properties");
        std::fs::write(&file, "# mine\ntestcontainers.reuse.enable=true").unwrap();
        let socket = Path::new("/s.sock");
        ensure_testcontainers_host(&file, socket).unwrap();
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "# mine\ntestcontainers.reuse.enable=true\ndocker.host=unix:///s.sock\n"
        );
        remove_testcontainers_host(&file, socket).unwrap();
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "# mine\ntestcontainers.reuse.enable=true\n"
        );
    }

    #[test]
    fn testcontainers_properties_leave_another_engine_alone() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(".testcontainers.properties");
        std::fs::write(&file, "docker.host = tcp://remote:2375\n").unwrap();
        assert_eq!(
            ensure_testcontainers_host(&file, Path::new("/s.sock")).unwrap(),
            PropertiesOutcome::Other("tcp://remote:2375".into())
        );
        remove_testcontainers_host(&file, Path::new("/s.sock")).unwrap();
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "docker.host = tcp://remote:2375\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn socket_link_replaces_only_our_links() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("run/docker.sock");
        let a = dir.path().join("a.sock");
        let b = dir.path().join("b.sock");
        link_socket(&link, &a).unwrap();
        assert_eq!(std::fs::read_link(&link).unwrap(), a);
        link_socket(&link, &b).unwrap();
        assert_eq!(std::fs::read_link(&link).unwrap(), b);
        // Unlinking with the wrong target keeps it.
        unlink_socket(&link, &a).unwrap();
        assert!(std::fs::symlink_metadata(&link).is_ok());
        unlink_socket(&link, &b).unwrap();
        assert!(std::fs::symlink_metadata(&link).is_err());
        // A real file is not replaced.
        std::fs::write(&link, b"x").unwrap();
        assert_eq!(
            link_socket(&link, &a).unwrap_err().kind(),
            std::io::ErrorKind::AlreadyExists
        );
        unlink_socket(&link, &a).unwrap();
        assert!(link.exists());
    }

    #[test]
    fn parses_engine_http_responses() {
        let ok = b"HTTP/1.0 200 OK\r\nApi-Version: 1.52\r\nContent-Length: 2\r\n\r\nOK";
        assert_eq!(parse_http_response(ok), Some((200, "OK".to_string())));
        assert_eq!(parse_http_response(b"garbage"), None);
        assert_eq!(parse_http_response(b"HTTP/1.0 abc\r\n\r\n"), None);
    }

    #[cfg(unix)]
    #[test]
    fn engine_probe_speaks_http_over_the_socket() {
        use std::io::Read;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("engine.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            for reply in [
                "HTTP/1.0 200 OK\r\n\r\nOK",
                "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{\"Version\":\"29.0.1\"}",
            ] {
                let (mut conn, _) = listener.accept().unwrap();
                let mut request = [0u8; 256];
                let n = conn.read(&mut request).unwrap();
                assert!(std::str::from_utf8(&request[..n])
                    .unwrap()
                    .starts_with("GET /"));
                conn.write_all(reply.as_bytes()).unwrap();
            }
        });
        assert!(engine_ready(&path));
        assert_eq!(engine_version(&path).as_deref(), Some("29.0.1"));
        server.join().unwrap();
        assert!(!engine_ready(&dir.path().join("missing.sock")));
    }
}
