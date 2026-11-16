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
pub struct ContainerDetails {
    pub id: String,
    pub name: String,
    pub image: String,
    pub state: String,
    pub started_at: String,
    pub health: Option<String>,
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
            health: v["State"]["Health"]["Status"].as_str().map(str::to_owned),
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
