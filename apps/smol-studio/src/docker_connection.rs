//! Bounded, read-only checks against the explicitly selected Smol Docker context.
use crate::runtime::{capture, find_tool};
use serde::Deserialize;
use std::{path::Path, process::Command, sync::atomic::AtomicBool, time::Duration};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum State {
    Ready,
    MissingCli,
    MissingContext,
    Unavailable,
    WrongEngine,
}
#[derive(Clone, Debug)]
pub struct Connection {
    pub state: State,
    pub cli: String,
    pub endpoint: Option<String>,
    pub engine: Option<String>,
    pub api: Option<String>,
    pub detail: Option<String>,
}
impl Connection {
    pub fn title(&self) -> &'static str {
        match self.state {
            State::Ready => "Connected to Smol",
            State::MissingCli => "Docker CLI is missing",
            State::MissingContext => "Connect your Docker tools",
            State::Unavailable => "Smol could not be reached",
            State::WrongEngine => "The smol context points to another engine",
        }
    }
    pub fn description(&self) -> &'static str {
        match self.state {
            State::Ready => "Docker commands in Studio use your Smol engine.",
            State::MissingCli => "Install the Docker CLI, then check the connection again.",
            State::MissingContext => {
                "Set up Smol once to use Docker, Compose and Buildx with your machines."
            }
            State::Unavailable => {
                "Check the connection again, or restore Smol’s Docker setup if the socket is no longer registered."
            }
            State::WrongEngine => "Restore Smol’s connection before managing containers here.",
        }
    }
    pub fn diagnostics(&self) -> String {
        format!(
            "{}\nDocker CLI: {}\nContext: smol\nEndpoint: {}\nEngine: {}\nAPI: {}\n{}",
            self.title(),
            self.cli,
            self.endpoint.as_deref().unwrap_or("Not configured"),
            self.engine.as_deref().unwrap_or("Not reported"),
            self.api.as_deref().unwrap_or("Not reported"),
            self.detail.as_deref().unwrap_or("")
        )
    }
}
#[derive(Deserialize)]
struct Context {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "DockerEndpoint")]
    endpoint: String,
}
fn endpoint(bytes: &[u8]) -> Result<Option<String>, String> {
    for line in bytes.split(|b| *b == b'\n').filter(|line| !line.is_empty()) {
        let context: Context =
            serde_json::from_slice(line).map_err(|_| "Docker returned an invalid context list.")?;
        if context.name == "smol" {
            return Ok(Some(context.endpoint));
        }
    }
    Ok(None)
}
fn server(report: &mut Connection, bytes: &[u8]) -> Result<(), String> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| "Docker returned an invalid engine version.")?;
    let platform = value["Platform"]["Name"]
        .as_str()
        .ok_or("The engine did not identify its platform.")?;
    report.engine = Some(platform.into());
    report.api = value["ApiVersion"].as_str().map(str::to_owned);
    report.state = if platform == "smolvm" || platform.starts_with("smolvm ") {
        State::Ready
    } else {
        State::WrongEngine
    };
    Ok(())
}
fn command(cli: &Path) -> Command {
    let mut command = Command::new(cli);
    command
        .env_remove("DOCKER_HOST")
        .env_remove("DOCKER_CONTEXT")
        .env("NO_COLOR", "1");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    command
}
pub fn check(shutdown: &AtomicBool) -> Connection {
    check_with(
        &find_tool(if cfg!(windows) {
            "docker.exe"
        } else {
            "docker"
        }),
        shutdown,
    )
}
fn check_with(cli: &Path, shutdown: &AtomicBool) -> Connection {
    let mut report = Connection {
        state: State::Unavailable,
        cli: cli.display().to_string(),
        endpoint: None,
        engine: None,
        api: None,
        detail: None,
    };
    if !cli.is_file() {
        report.state = State::MissingCli;
        return report;
    }
    let check = (|| {
        let bytes = capture(
            command(cli).args(["context", "ls", "--format", "{{json .}}"]),
            Duration::from_secs(10),
            256 * 1024,
            shutdown,
        )?;
        report.endpoint = endpoint(&bytes)?;
        if report.endpoint.is_none() {
            report.state = State::MissingContext;
            return Ok(());
        }
        let bytes = capture(
            command(cli).args([
                "--context",
                "smol",
                "version",
                "--format",
                "{{json .Server}}",
            ]),
            Duration::from_secs(15),
            256 * 1024,
            shutdown,
        )?;
        server(&mut report, &bytes)
    })();
    if let Err(error) = check {
        report.detail = Some(error);
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn context_and_server_are_explicit_and_unambiguous() {
        assert_eq!(
            endpoint(
                br#"{"Name":"desktop-linux","DockerEndpoint":"unix:///other"}
{"Name":"smol","DockerEndpoint":"unix:///smol"}"#
            )
            .unwrap()
            .as_deref(),
            Some("unix:///smol")
        );
        assert!(endpoint(b"not json").is_err());
        assert!(
            endpoint(br#"{"Name":"other","DockerEndpoint":"unix:///other"}"#)
                .unwrap()
                .is_none()
        );
        let mut report = check_with(
            Path::new("/no-such-studio-test-docker"),
            &AtomicBool::new(false),
        );
        assert_eq!(report.state, State::MissingCli);
        server(
            &mut report,
            br#"{"Platform":{"Name":"Docker Desktop"},"ApiVersion":"1.47"}"#,
        )
        .unwrap();
        assert_eq!(report.state, State::WrongEngine);
        server(
            &mut report,
            br#"{"Platform":{"Name":"smolvm 1.35.0"},"ApiVersion":"1.47"}"#,
        )
        .unwrap();
        assert_eq!(report.state, State::Ready);
        assert!(server(&mut report, b"null").is_err());
    }
    #[cfg(unix)]
    #[test]
    fn probe_uses_only_named_context_and_preserves_setup() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let cli = temp.path().join("docker");
        // Reject extra commands or ambient context/host leakage. No real Docker setup is touched.
        std::fs::write(
            &cli,
            r#"#!/bin/sh
[ -z "$DOCKER_HOST" ] && [ -z "$DOCKER_CONTEXT" ] || exit 9
if [ "$1 $2 $3 $4" = 'context ls --format {{json .}}' ]; then
 echo '{"Name":"smol","DockerEndpoint":"unix:///fixture"}'
elif [ "$1 $2 $3 $4 $5" = '--context smol version --format {{json .Server}}' ]; then
 echo '{"Platform":{"Name":"smolvm test"},"ApiVersion":"1.47"}'
else exit 8; fi
"#,
        )
        .unwrap();
        std::fs::set_permissions(&cli, std::fs::Permissions::from_mode(0o755)).unwrap();
        let report = check_with(&cli, &AtomicBool::new(false));
        assert_eq!(report.state, State::Ready, "{:?}", report.detail);
        assert_eq!(report.endpoint.as_deref(), Some("unix:///fixture"));
    }
}
