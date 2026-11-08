//! Docker Engine API request bodies, as the clients send them.
//!
//! Only the fields the engine acts on are typed; everything else a client
//! sends is kept verbatim in the container record and echoed back by inspect.

use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeMap;

/// The newest API version the engine answers to.
pub const API_VERSION: &str = "1.51";

/// The oldest API version the engine accepts. Kept low on purpose: older
/// Testcontainers and docker-java releases still ask for 1.32.
pub const MIN_API_VERSION: &str = "1.24";

/// The Docker engine version the engine reports. Clients compare it for
/// feature checks, so it names the Docker release whose API it implements.
pub const ENGINE_VERSION: &str = "28.5.0";

/// A list that a client may send as `null`, a single string, or an array.
pub(crate) fn string_or_list<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }
    Ok(match Option::<OneOrMany>::deserialize(deserializer)? {
        None => None,
        Some(OneOrMany::One(s)) => Some(vec![s]),
        Some(OneOrMany::Many(v)) => Some(v),
    })
}

fn null_as_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

/// `Config` of a container create request.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", default)]
pub(crate) struct ContainerConfig {
    pub hostname: String,
    pub domainname: String,
    pub user: String,
    pub attach_stdin: bool,
    pub attach_stdout: bool,
    pub attach_stderr: bool,
    #[serde(deserialize_with = "null_as_default")]
    pub exposed_ports: BTreeMap<String, serde_json::Value>,
    pub tty: bool,
    pub open_stdin: bool,
    pub stdin_once: bool,
    #[serde(deserialize_with = "null_as_default")]
    pub env: Vec<String>,
    #[serde(deserialize_with = "string_or_list")]
    pub cmd: Option<Vec<String>>,
    pub healthcheck: Option<HealthConfig>,
    pub image: String,
    #[serde(deserialize_with = "null_as_default")]
    pub volumes: BTreeMap<String, serde_json::Value>,
    pub working_dir: String,
    #[serde(deserialize_with = "string_or_list")]
    pub entrypoint: Option<Vec<String>>,
    pub network_disabled: bool,
    #[serde(deserialize_with = "null_as_default")]
    pub labels: BTreeMap<String, String>,
    pub stop_signal: Option<String>,
    pub stop_timeout: Option<i64>,
}

/// A container's health check (`Config.Healthcheck`), durations in nanoseconds.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "PascalCase", default)]
pub(crate) struct HealthConfig {
    #[serde(deserialize_with = "null_as_default")]
    pub test: Vec<String>,
    pub interval: i64,
    pub timeout: i64,
    pub start_period: i64,
    pub start_interval: i64,
    pub retries: i64,
}

/// `HostConfig` of a container create request.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", default)]
pub(crate) struct HostConfig {
    #[serde(deserialize_with = "null_as_default")]
    pub binds: Vec<String>,
    pub network_mode: String,
    #[serde(deserialize_with = "null_as_default")]
    pub port_bindings: BTreeMap<String, Option<Vec<PortBinding>>>,
    pub restart_policy: RestartPolicy,
    pub auto_remove: bool,
    #[serde(deserialize_with = "null_as_default")]
    pub volumes_from: Vec<String>,
    #[serde(deserialize_with = "null_as_default")]
    pub mounts: Vec<Mount>,
    #[serde(deserialize_with = "null_as_default")]
    pub dns: Vec<String>,
    #[serde(deserialize_with = "null_as_default")]
    pub dns_options: Vec<String>,
    #[serde(deserialize_with = "null_as_default")]
    pub dns_search: Vec<String>,
    #[serde(deserialize_with = "null_as_default")]
    pub extra_hosts: Vec<String>,
    #[serde(deserialize_with = "null_as_default")]
    pub links: Vec<String>,
    pub privileged: bool,
    pub publish_all_ports: bool,
    pub readonly_rootfs: bool,
    #[serde(deserialize_with = "null_as_default")]
    pub tmpfs: BTreeMap<String, String>,
    pub shm_size: i64,
    pub memory: i64,
    pub nano_cpus: i64,
    pub cpu_quota: i64,
    pub cpu_period: i64,
    pub init: Option<bool>,
}

/// One host binding of a container port.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase", default)]
pub(crate) struct PortBinding {
    pub host_ip: String,
    pub host_port: String,
}

/// `HostConfig.RestartPolicy`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase", default)]
pub(crate) struct RestartPolicy {
    pub name: String,
    pub maximum_retry_count: i64,
}

/// One `HostConfig.Mounts` entry.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", default)]
pub(crate) struct Mount {
    #[serde(rename = "Type")]
    pub kind: String,
    pub source: String,
    pub target: String,
    pub read_only: bool,
    pub volume_options: Option<VolumeOptions>,
    pub tmpfs_options: Option<TmpfsOptions>,
}

/// `VolumeOptions` of a volume mount.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", default)]
pub(crate) struct VolumeOptions {
    pub no_copy: bool,
    #[serde(deserialize_with = "null_as_default")]
    pub labels: BTreeMap<String, String>,
    pub subpath: String,
}

/// `TmpfsOptions` of a tmpfs mount.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", default)]
pub(crate) struct TmpfsOptions {
    pub size_bytes: i64,
    pub mode: u32,
}

/// `NetworkingConfig` of a container create request.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", default)]
pub(crate) struct NetworkingConfig {
    #[serde(deserialize_with = "null_as_default")]
    pub endpoints_config: BTreeMap<String, EndpointSettings>,
}

/// One network a container joins, as a client asks for it.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "PascalCase", default)]
pub(crate) struct EndpointSettings {
    #[serde(rename = "IPAMConfig")]
    pub ipam_config: Option<EndpointIpam>,
    #[serde(deserialize_with = "null_as_default")]
    pub aliases: Vec<String>,
    #[serde(deserialize_with = "null_as_default")]
    pub links: Vec<String>,
    pub mac_address: String,
    #[serde(rename = "DNSNames", deserialize_with = "null_as_default")]
    pub dns_names: Vec<String>,
}

/// A fixed address asked for on a network.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub(crate) struct EndpointIpam {
    #[serde(rename = "IPv4Address")]
    pub ipv4_address: String,
}

/// The body of `POST /containers/create`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub(crate) struct CreateRequest {
    #[serde(flatten)]
    pub config: ContainerConfig,
    pub host_config: HostConfig,
    pub networking_config: NetworkingConfig,
}

/// The body of `POST /containers/{id}/exec`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub(crate) struct ExecCreateRequest {
    pub attach_stdin: bool,
    pub attach_stdout: bool,
    pub attach_stderr: bool,
    pub tty: bool,
    #[serde(deserialize_with = "null_as_default")]
    pub env: Vec<String>,
    #[serde(deserialize_with = "string_or_list")]
    pub cmd: Option<Vec<String>>,
    pub user: String,
    pub working_dir: String,
    pub privileged: bool,
    pub console_size: Option<Vec<u16>>,
}

/// The body of `POST /exec/{id}/start`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub(crate) struct ExecStartRequest {
    pub detach: bool,
    pub tty: bool,
    pub console_size: Option<Vec<u16>>,
}

/// The body of `POST /networks/create`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub(crate) struct NetworkCreateRequest {
    pub name: String,
    pub driver: String,
    pub internal: bool,
    pub attachable: bool,
    #[serde(rename = "EnableIPv6")]
    pub enable_ipv6: Option<bool>,
    #[serde(rename = "IPAM")]
    pub ipam: Option<Ipam>,
    #[serde(deserialize_with = "null_as_default")]
    pub options: BTreeMap<String, String>,
    #[serde(deserialize_with = "null_as_default")]
    pub labels: BTreeMap<String, String>,
    pub check_duplicate: Option<bool>,
}

/// `IPAM` of a network create request.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", default)]
pub(crate) struct Ipam {
    pub driver: String,
    #[serde(deserialize_with = "null_as_default")]
    pub config: Vec<IpamConfig>,
}

/// One address pool of a network.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", default)]
pub(crate) struct IpamConfig {
    pub subnet: String,
    #[serde(rename = "IPRange")]
    pub ip_range: String,
    pub gateway: String,
}

/// The body of `POST /networks/{id}/connect`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub(crate) struct NetworkConnectRequest {
    pub container: String,
    pub endpoint_config: Option<EndpointSettings>,
}

/// The body of `POST /networks/{id}/disconnect`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub(crate) struct NetworkDisconnectRequest {
    pub container: String,
    pub force: bool,
}

/// The body of `POST /volumes/create`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub(crate) struct VolumeCreateRequest {
    pub name: String,
    pub driver: String,
    #[serde(deserialize_with = "null_as_default")]
    pub driver_opts: BTreeMap<String, String>,
    #[serde(deserialize_with = "null_as_default")]
    pub labels: BTreeMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_request_takes_what_the_docker_cli_sends() {
        let body = r#"{"Hostname":"","Domainname":"","User":"","AttachStdin":false,
            "AttachStdout":true,"AttachStderr":true,"Tty":false,"OpenStdin":false,
            "StdinOnce":false,"Env":null,"Cmd":["echo","hi"],"Image":"alpine",
            "Volumes":{},"WorkingDir":"","Entrypoint":null,"OnBuild":null,"Labels":{},
            "HostConfig":{"Binds":null,"NetworkMode":"default","PortBindings":{"80/tcp":[{"HostIp":"","HostPort":"8080"}]},
            "RestartPolicy":{"Name":"no","MaximumRetryCount":0},"AutoRemove":true,
            "Mounts":null,"Tmpfs":null,"ShmSize":0},
            "NetworkingConfig":{"EndpointsConfig":{}}}"#;
        let req: CreateRequest = serde_json::from_str(body).unwrap();
        assert_eq!(req.config.cmd, Some(vec!["echo".into(), "hi".into()]));
        assert_eq!(req.config.entrypoint, None);
        assert!(req.host_config.auto_remove);
        assert_eq!(
            req.host_config.port_bindings["80/tcp"].as_ref().unwrap()[0].host_port,
            "8080"
        );
    }

    #[test]
    fn a_string_entrypoint_is_a_one_element_list() {
        let c: ContainerConfig =
            serde_json::from_str(r#"{"Entrypoint":"/bin/sh","Cmd":null}"#).unwrap();
        assert_eq!(c.entrypoint, Some(vec!["/bin/sh".into()]));
        assert_eq!(c.cmd, None);
    }
}
