//! Display-only projection of Docker inspect; environment variables and registry
//! credentials are deliberately not retained in the desktop model.
use serde_json::Value;
use std::net::IpAddr;

#[derive(Clone, Debug)]
pub struct PublishedPort {
    pub container: String,
    pub host_ip: String,
    pub host_port: String,
}
impl PublishedPort {
    pub fn browser_url(&self) -> Option<String> {
        if !self.container.ends_with("/tcp") {
            return None;
        }
        let port: u16 = self.host_port.parse().ok().filter(|p| *p != 0)?;
        let address: IpAddr = if self.host_ip.is_empty() {
            "127.0.0.1".parse().ok()?
        } else {
            self.host_ip.parse().ok()?
        };
        let host = match address {
            IpAddr::V4(ip) if ip.is_unspecified() => "127.0.0.1".into(),
            IpAddr::V6(ip) if ip.is_unspecified() => "[::1]".into(),
            IpAddr::V4(ip) => ip.to_string(),
            IpAddr::V6(ip) => format!("[{ip}]"),
        };
        Some(format!("http://{host}:{port}/"))
    }
}
#[derive(Clone, Debug)]
pub struct Mount {
    pub source: String,
    pub target: String,
    pub kind: String,
    pub writable: bool,
}
#[derive(Clone, Debug)]
pub struct HealthProbe {
    pub exit_code: Option<i64>,
    pub finished_at: String,
    pub output: String,
    pub truncated: bool,
}

impl HealthProbe {
    pub fn reported_at(&self) -> String {
        crate::storage::display_time(&self.finished_at)
    }
}

pub struct ExitSummary {
    pub title: String,
    pub explanation: &'static str,
}

#[derive(Clone, Debug)]
pub struct ContainerDetails {
    pub id: String,
    pub name: String,
    pub image: String,
    pub state: String,
    pub started_at: String,
    pub health: Option<String>,
    pub health_probe: Option<HealthProbe>,
    pub health_failures: Option<u64>,
    pub exit_code: Option<i64>,
    pub error: String,
    pub oom_killed: bool,
    pub restarts: u64,
    pub ports: Vec<PublishedPort>,
    pub mounts: Vec<Mount>,
    pub project: Option<String>,
    pub service: Option<String>,
    pub command: Vec<String>,
}
fn text(value: &Value) -> String {
    value.as_str().unwrap_or_default().to_owned()
}
impl ContainerDetails {
    pub fn can_start(&self) -> bool {
        matches!(self.state.as_str(), "created" | "exited")
    }

    pub fn can_stop(&self) -> bool {
        matches!(self.state.as_str(), "running" | "paused" | "restarting")
    }

    pub fn can_remove(&self) -> bool {
        matches!(self.state.as_str(), "created" | "exited" | "dead")
    }

    pub fn can_rename(&self) -> bool {
        self.can_start() || self.can_stop() || self.state == "dead"
    }

    pub fn state_notice(&self) -> Option<&'static str> {
        match self.state.as_str() {
            "running" | "created" | "exited" => None,
            "paused" => Some("Resume this container to continue its work and open a terminal."),
            "restarting" => {
                Some("Waiting for this container to restart. Stop it to end the restart cycle.")
            }
            "removing" => Some("This container is being removed."),
            "dead" => Some("This container cannot be started. Review its logs before removing it."),
            _ => Some("Container state is unavailable. Refresh to check its status."),
        }
    }

    pub fn exit_summary(&self) -> Option<ExitSummary> {
        if !matches!(self.state.as_str(), "exited" | "dead") {
            return None;
        }
        let (title, explanation) = if self.oom_killed {
            (
                "Stopped after running out of memory".into(),
                "Review memory use and the application logs before starting again.",
            )
        } else if self.exit_code == Some(0) {
            (
                "Command completed".into(),
                "The container command finished successfully.",
            )
        } else {
            (
                self.exit_code
                    .map(|code| format!("Exited with code {code}"))
                    .unwrap_or_else(|| "Container stopped".into()),
                "The command has stopped. Check the logs for its last output.",
            )
        };
        Some(ExitSummary { title, explanation })
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let v: Value = serde_json::from_slice(bytes)
            .map_err(|_| "Docker returned invalid container details.")?;
        let id = text(&v["Id"]);
        if id.is_empty() || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("Docker returned an invalid container ID.".into());
        }
        let mut ports = vec![];
        let port_bindings = if v["State"]["Status"].as_str() == Some("running") {
            &v["NetworkSettings"]["Ports"]
        } else if v["HostConfig"]["PortBindings"].is_object() {
            &v["HostConfig"]["PortBindings"]
        } else {
            &v["NetworkSettings"]["Ports"]
        };
        if let Some(bindings) = port_bindings.as_object() {
            for (container, bindings) in bindings {
                if let Some(bindings) = bindings.as_array() {
                    for binding in bindings {
                        ports.push(PublishedPort {
                            container: container.clone(),
                            host_ip: text(&binding["HostIp"]),
                            host_port: text(&binding["HostPort"]),
                        });
                    }
                }
            }
        }
        let mounts = v["Mounts"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|m| Mount {
                source: text(&m["Source"]),
                target: text(&m["Destination"]),
                kind: text(&m["Type"]),
                writable: m["RW"].as_bool().unwrap_or(false),
            })
            .collect();
        let mut command = vec![];
        for key in ["Entrypoint", "Cmd"] {
            if let Some(args) = v["Config"][key].as_array() {
                command.extend(args.iter().filter_map(Value::as_str).map(str::to_owned));
            }
        }
        Ok(Self {
            id,
            name: text(&v["Name"]).trim_start_matches('/').into(),
            image: text(&v["Config"]["Image"]),
            state: text(&v["State"]["Status"]),
            started_at: text(&v["State"]["StartedAt"]),
            health: v["State"]["Health"]["Status"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(str::to_owned),
            health_failures: v["State"]["Health"]["FailingStreak"].as_u64(),
            health_probe: v["State"]["Health"]["Log"]
                .as_array()
                .and_then(|log| log.last())
                .filter(|probe| probe.is_object())
                .map(|probe| {
                    let output = probe["Output"].as_str().unwrap_or_default();
                    HealthProbe {
                        exit_code: probe["ExitCode"].as_i64(),
                        finished_at: text(&probe["End"]).chars().take(128).collect(),
                        output: output.chars().take(4096).collect(),
                        truncated: output.chars().nth(4096).is_some(),
                    }
                }),
            exit_code: v["State"]["ExitCode"].as_i64(),
            error: text(&v["State"]["Error"]),
            oom_killed: v["State"]["OOMKilled"].as_bool().unwrap_or(false),
            restarts: v["RestartCount"].as_u64().unwrap_or(0),
            ports,
            mounts,
            project: v["Config"]["Labels"]["com.docker.compose.project"]
                .as_str()
                .map(str::to_owned),
            service: v["Config"]["Labels"]["com.docker.compose.service"]
                .as_str()
                .map(str::to_owned),
            command,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn paused_and_transitional_containers_do_not_offer_start_or_remove() {
        for (state, start, stop, remove, rename) in [
            ("created", true, false, true, true),
            ("exited", true, false, true, true),
            ("running", false, true, false, true),
            ("paused", false, true, false, true),
            ("restarting", false, true, false, true),
            ("removing", false, false, false, false),
            ("dead", false, false, true, true),
            ("", false, false, false, false),
            ("future-state", false, false, false, false),
        ] {
            let d = ContainerDetails::parse(
                &serde_json::to_vec(&serde_json::json!({"Id":"abcdef", "State":{"Status":state}}))
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(
                (d.can_start(), d.can_stop(), d.can_remove(), d.can_rename()),
                (start, stop, remove, rename),
                "{state}"
            );
        }
    }

    #[test]
    #[ignore = "requires an explicitly owned health-check container in an isolated smol context"]
    fn live_health_projection_reports_the_current_check() {
        use crate::{
            docker::{Action, DockerWorker, Output},
            runtime::Runtime,
        };
        let id = std::env::var("SMOL_STUDIO_HEALTH_ID").expect("owned container ID");
        let expected = std::env::var("SMOL_STUDIO_HEALTH_EXPECT").expect("expected health");
        let worker = DockerWorker::new(|| {});
        worker
            .submit(Runtime::discover(), Action::Inspect(id.clone()))
            .unwrap();
        let Output::Details(d) = worker
            .events
            .recv_timeout(std::time::Duration::from_secs(30))
            .unwrap()
            .result
            .unwrap()
        else {
            panic!("expected container details");
        };
        assert_eq!(d.id, id);
        assert_eq!(d.state, "running");
        assert_eq!(d.health.as_deref(), Some(expected.as_str()));
        let probe = d.health_probe.as_ref().expect("latest probe");
        if expected == "unhealthy" {
            assert_eq!(probe.exit_code, Some(1));
            assert!(probe.output.contains("dependency unavailable"));
            assert!(d.health_failures.unwrap() >= 1);
        } else {
            assert_eq!(expected, "healthy");
            assert_eq!(probe.exit_code, Some(0));
            assert!(probe.output.contains("ready"));
            assert_eq!(d.health_failures, Some(0));
        }
        assert!(!probe.finished_at.is_empty());
        assert!(!probe.truncated);
        assert!(d.exit_summary().is_none());
    }

    #[test]
    fn exit_codes_do_not_guess_oom_and_running_containers_have_no_exit_summary() {
        let mut v = serde_json::json!({"Id":"abcdef","State":{"Status":"exited","ExitCode":137,"OOMKilled":false}});
        let parse = |v: &Value| ContainerDetails::parse(&serde_json::to_vec(v).unwrap()).unwrap();
        assert_eq!(
            parse(&v).exit_summary().unwrap().title,
            "Exited with code 137"
        );
        v["State"]["OOMKilled"] = true.into();
        assert_eq!(
            parse(&v).exit_summary().unwrap().title,
            "Stopped after running out of memory"
        );
        v["State"]["Status"] = "running".into();
        assert!(parse(&v).exit_summary().is_none());
        v["State"] = serde_json::json!({"Status":"exited","ExitCode":0});
        assert_eq!(parse(&v).exit_summary().unwrap().title, "Command completed");
    }

    #[test]
    fn health_projection_keeps_latest_report_and_bounds_unicode_output() {
        let mut v = serde_json::json!({"Id":"abcdef","Config":{"Env":["TOKEN=secret"]},"State":{"Status":"running","Health":{"Status":"healthy","FailingStreak":0,"Log":[{"ExitCode":1,"Output":"old failure"},{"ExitCode":0,"Output":"ready","End":"2026-11-15T12:00:00Z"}]}}});
        let parse = |v: &Value| ContainerDetails::parse(&serde_json::to_vec(v).unwrap()).unwrap();
        let d = parse(&v);
        assert_eq!(d.health.as_deref(), Some("healthy"));
        assert_eq!(d.health_failures, Some(0));
        let probe = d.health_probe.as_ref().unwrap();
        assert_eq!(probe.reported_at(), "2026-11-15 12:00:00 UTC");
        assert_eq!(probe.output, "ready");
        assert_eq!(probe.exit_code, Some(0));
        assert!(!probe.truncated);
        assert!(!format!("{d:?}").contains("secret"));
        v["State"]["Health"]["Log"][1]["Output"] = "☁".repeat(5000).into();
        let d = parse(&v);
        let probe = d.health_probe.unwrap();
        assert_eq!(probe.output.chars().count(), 4096);
        assert!(probe.truncated);
        v["State"]["Health"]["Log"] = serde_json::json!([]);
        assert!(parse(&v).health_probe.is_none());
    }

    #[test]
    fn published_urls_handle_wildcards_ipv6_udp_and_untrusted_metadata() {
        let port = |ip: &str, p: &str, protocol: &str| {
            PublishedPort {
                container: format!("80/{protocol}"),
                host_ip: ip.into(),
                host_port: p.into(),
            }
            .browser_url()
        };
        assert_eq!(
            port("0.0.0.0", "8080", "tcp").as_deref(),
            Some("http://127.0.0.1:8080/")
        );
        assert_eq!(
            port("::", "8080", "tcp").as_deref(),
            Some("http://[::1]:8080/")
        );
        assert_eq!(
            port("::1", "8080", "tcp").as_deref(),
            Some("http://[::1]:8080/")
        );
        assert_eq!(port("127.0.0.1", "53", "udp"), None);
        assert_eq!(port("example.com/steal", "80", "tcp"), None);
        assert_eq!(port("127.0.0.1", "0", "tcp"), None);
        assert_eq!(port("127.0.0.1", "70000", "tcp"), None);
    }
    #[test]
    fn inspect_preserves_diagnostics_but_does_not_retain_environment() {
        let d=ContainerDetails::parse(br#"{"Id":"abcdef","Name":"/api","Config":{"Image":"alpine","Env":["TOKEN=secret"],"Entrypoint":["sh"],"Cmd":["-c","exit 7"],"Labels":{"com.docker.compose.project":"web"}},"State":{"Status":"exited","ExitCode":7,"OOMKilled":true},"Mounts":[{"Source":"/tmp/source","Destination":"/work","Type":"bind","RW":false}],"NetworkSettings":{"Ports":{"80/tcp":[{"HostIp":"0.0.0.0","HostPort":"8080"}],"53/udp":null}}}"#).unwrap();
        assert_eq!(d.name, "api");
        assert_eq!(d.exit_code, Some(7));
        assert!(d.oom_killed);
        assert!(!d.mounts[0].writable);
        assert_eq!(d.ports.len(), 1);
        assert_eq!(d.command, vec!["sh", "-c", "exit 7"]);
        assert!(!format!("{d:?}").contains("secret"));
    }
    #[test]
    fn stopped_ports_use_configuration_and_running_ports_use_actual_bindings() {
        let mut v = serde_json::json!({"Id":"abcdef","State":{"Status":"exited"},"HostConfig":{"PortBindings":{"80/tcp":[{"HostIp":"127.0.0.1","HostPort":"8080"}]}},"NetworkSettings":{"Ports":{"80/tcp":[{"HostIp":"127.0.0.1","HostPort":"49152"}]}}});
        let parse = |v: &serde_json::Value| {
            ContainerDetails::parse(&serde_json::to_vec(v).unwrap()).unwrap()
        };
        assert_eq!(parse(&v).ports[0].host_port, "8080");
        v["State"]["Status"] = "running".into();
        assert_eq!(parse(&v).ports[0].host_port, "49152");
        v["NetworkSettings"]["Ports"] = serde_json::json!({});
        assert!(parse(&v).ports.is_empty());
    }
}
