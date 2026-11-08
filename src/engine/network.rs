//! Container networks: Docker's default ones.
//!
//! Every container is its own machine with its own network stack on the
//! host, so the network between containers is not a bridge in one kernel: it
//! is the container switch ([`smolvm_network::switch`]), a directory this
//! module owns and every container's stack reads. A container on the default
//! `bridge` network gets an address on its subnet, reaches the other
//! containers on it by address, and resolves no names, as in Docker; `--link`
//! names go in its `/etc/hosts`. `host` and `none` are listed as Docker lists
//! them. User-defined networks are not here yet.
//!
//! The engine writes, the stacks read:
//!
//! - `ep/<container>.json`: the container's addresses, primary first;
//! - `n/<network>/<address>`: a link to the container's endpoint socket,
//!   which is both its membership and its route.
//!
//! A container reaches the host as `host.docker.internal`, its gateway, which
//! its stack answers for the host.

use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::containers::{Container, ContainerRecord, EndpointRecord};
use super::filters::Filters;
use super::model::{CreateRequest, EndpointSettings};
use super::store::Store;
use super::util::{ApiError, ApiResult};
use super::Engine;

/// The default network's subnet, as Docker's.
const BRIDGE_SUBNET: &str = "172.17.0.0/16";

/// One network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct NetworkRecord {
    pub id: String,
    pub name: String,
    pub driver: String,
    pub created: String,
    /// `a.b.c.d/len`; empty for `host` and `none`.
    pub subnet: String,
    pub gateway: String,
    #[serde(default)]
    pub ip_range: String,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    #[serde(default)]
    pub options: BTreeMap<String, String>,
    #[serde(default)]
    pub internal: bool,
    #[serde(default)]
    pub attachable: bool,
    #[serde(default)]
    pub builtin: bool,
}

impl NetworkRecord {
    fn short(&self) -> &str {
        &self.id[..12]
    }

    fn net(&self) -> Option<(Ipv4Addr, u8)> {
        let (ip, len) = self.subnet.split_once('/')?;
        let ip: Ipv4Addr = ip.parse().ok()?;
        let len: u8 = len.parse().ok().filter(|l| *l <= 30)?;
        Some((Ipv4Addr::from(u32::from(ip) & mask(len)), len))
    }

    /// Whether containers on it can be addressed (not `host` or `none`).
    fn routable(&self) -> bool {
        self.net().is_some()
    }
}

fn mask(len: u8) -> u32 {
    if len == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(len))
    }
}

/// The engine's networks and its end of the switch.
pub(crate) struct Networks {
    records: parking_lot::RwLock<HashMap<String, NetworkRecord>>,
    /// The switch directory.
    dir: PathBuf,
    /// Serializes address allocation and switch writes.
    lock: tokio::sync::Mutex<()>,
}

impl Networks {
    pub(crate) fn load(store: &Store, socket: &Path) -> crate::Result<Self> {
        let mut records: HashMap<String, NetworkRecord> = store
            .load_objects::<NetworkRecord>("networks")?
            .into_iter()
            .map(|r| (r.id.clone(), r))
            .collect();
        for (name, driver, subnet) in [
            ("bridge", "bridge", BRIDGE_SUBNET),
            ("host", "host", ""),
            ("none", "null", ""),
        ] {
            if !records.values().any(|r| r.name == name && r.builtin) {
                let record = NetworkRecord {
                    id: builtin_id(name),
                    name: name.into(),
                    driver: driver.into(),
                    created: super::util::now_rfc3339(),
                    subnet: subnet.into(),
                    gateway: if subnet.is_empty() {
                        String::new()
                    } else {
                        "172.17.0.1".into()
                    },
                    ip_range: String::new(),
                    labels: BTreeMap::new(),
                    options: BTreeMap::new(),
                    internal: false,
                    attachable: false,
                    builtin: true,
                };
                store.save_object("networks", &record.id, &record)?;
                records.insert(record.id.clone(), record);
            }
        }
        // The switch sits next to the API socket: its endpoint sockets need
        // a short path, and state from an earlier run means nothing now.
        let dir = socket
            .parent()
            .map(|p| p.join("sw"))
            .unwrap_or_else(|| PathBuf::from("/tmp/smolvm-sw"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("ep"))?;
        std::fs::create_dir_all(dir.join("n"))?;
        Ok(Self {
            records: parking_lot::RwLock::new(records),
            dir,
            lock: tokio::sync::Mutex::new(()),
        })
    }

    pub(crate) fn switch_dir(&self) -> &Path {
        &self.dir
    }

    /// The network `name_or_id` names: a name, a full id or a unique prefix.
    pub(crate) fn find(&self, name_or_id: &str) -> Option<NetworkRecord> {
        let records = self.records.read();
        if let Some(r) = records.values().find(|r| r.name == name_or_id) {
            return Some(r.clone());
        }
        if let Some(r) = records.get(name_or_id) {
            return Some(r.clone());
        }
        let mut matches = records.values().filter(|r| r.id.starts_with(name_or_id));
        match (matches.next(), matches.next()) {
            (Some(r), None) if !name_or_id.is_empty() => Some(r.clone()),
            _ => None,
        }
    }

    pub(crate) fn all(&self) -> Vec<NetworkRecord> {
        self.records.read().values().cloned().collect()
    }
}

fn builtin_id(name: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(
        format!("smolvm-engine-{name}").as_bytes(),
    ))
}

/// The network a container's `NetworkMode` names: `bridge` for the default,
/// `none`, or a network by name or id. `host` falls back to the default
/// network: a container is its own machine and has no host network to share.
fn mode_network(mode: &str) -> &str {
    match mode {
        "" | "default" | "host" => "bridge",
        other => other,
    }
}

/// The networks a new container joins, keyed by network name.
pub(crate) fn attach_at_create(
    engine: &Engine,
    _id: &str,
    name: &str,
    req: &CreateRequest,
) -> ApiResult<BTreeMap<String, EndpointRecord>> {
    let mode = mode_network(&req.host_config.network_mode);
    let mut out = BTreeMap::new();
    if mode == "none" {
        return Ok(out);
    }
    let primary = engine
        .networks
        .find(mode)
        .ok_or_else(|| ApiError::not_found(format!("network {mode} not found")))?;
    let mut wanted: Vec<(NetworkRecord, EndpointSettings)> = Vec::new();
    let mut primary_settings = EndpointSettings::default();
    for (key, settings) in &req.networking_config.endpoints_config {
        // The docker CLI keys the default network's settings as `default`.
        let key = mode_network(key);
        let network = engine
            .networks
            .find(key)
            .ok_or_else(|| ApiError::not_found(format!("network {key} not found")))?;
        if network.id == primary.id {
            primary_settings = settings.clone();
        } else {
            wanted.push((network, settings.clone()));
        }
    }
    wanted.insert(0, (primary, primary_settings));
    for (network, settings) in wanted {
        if network.routable() {
            out.insert(
                network.name.clone(),
                endpoint_for(&network, &settings, name),
            );
        }
    }
    Ok(out)
}

fn endpoint_for(
    network: &NetworkRecord,
    settings: &EndpointSettings,
    name: &str,
) -> EndpointRecord {
    let mut aliases = settings.aliases.clone();
    aliases.retain(|a| a != name);
    EndpointRecord {
        network_id: network.id.clone(),
        endpoint_id: String::new(),
        aliases,
        requested_ip: settings
            .ipam_config
            .as_ref()
            .map(|c| c.ipv4_address.clone())
            .unwrap_or_default(),
        ip: String::new(),
        prefix_len: 0,
        gateway: String::new(),
        mac: String::new(),
        links: settings.links.clone(),
    }
}

/// The container's networks, primary first.
fn ordered(record: &ContainerRecord) -> Vec<(String, EndpointRecord)> {
    let primary = mode_network(&record.host_config.network_mode).to_string();
    let mut out: Vec<(String, EndpointRecord)> = Vec::new();
    for (name, ep) in &record.networks {
        if name == &primary || ep.network_id.starts_with(&primary) {
            out.insert(0, (name.clone(), ep.clone()));
        } else {
            out.push((name.clone(), ep.clone()));
        }
    }
    out
}

/// The machine's endpoint on the switch.
pub(crate) fn attachment(engine: &Engine, id: &str) -> crate::data::network::SwitchAttachment {
    crate::data::network::SwitchAttachment {
        dir: engine.networks.switch_dir().to_path_buf(),
        endpoint: id[..12].to_string(),
    }
}

/// Addresses in use on a network by containers other than `except`.
fn used_addresses(engine: &Engine, network: &str, except: &str) -> Vec<Ipv4Addr> {
    engine
        .containers
        .read()
        .values()
        .filter(|c| c.id() != except)
        .filter_map(|c| {
            c.record()
                .networks
                .get(network)
                .and_then(|ep| ep.ip.parse().ok())
        })
        .collect()
}

/// Pick an address on `network` for container `id`.
fn allocate(
    engine: &Engine,
    network: &NetworkRecord,
    requested: &str,
    id: &str,
) -> ApiResult<Ipv4Addr> {
    let (net, len) = network.net().ok_or_else(|| {
        ApiError::bad_request(format!("network {} has no addresses", network.name))
    })?;
    let used = used_addresses(engine, &network.name, id);
    let gateway: Ipv4Addr = network
        .gateway
        .parse()
        .unwrap_or(Ipv4Addr::from(u32::from(net) + 1));
    let broadcast = u32::from(net) | !mask(len);
    if !requested.is_empty() {
        let ip: Ipv4Addr = requested
            .parse()
            .map_err(|_| ApiError::bad_request(format!("invalid address {requested}")))?;
        let n = u32::from(ip);
        if n & mask(len) != u32::from(net) || ip == gateway || n == u32::from(net) || n == broadcast
        {
            return Err(ApiError::bad_request(format!(
                "address {ip} is not usable on network {}",
                network.name
            )));
        }
        if used.contains(&ip) {
            return Err(ApiError::conflict(format!(
                "Address already in use: {ip} on network {}",
                network.name
            )));
        }
        return Ok(ip);
    }
    let (start, end) = match network.ip_range.split_once('/') {
        Some((ip, l)) => {
            let ip: Ipv4Addr = ip.parse().unwrap_or(net);
            let l: u8 = l.parse().unwrap_or(len);
            let s = u32::from(ip) & mask(l);
            (s, s | !mask(l))
        }
        None => (u32::from(net), broadcast),
    };
    (start.max(u32::from(net) + 1)..end.min(broadcast))
        .map(Ipv4Addr::from)
        .find(|ip| *ip != gateway && !used.contains(ip))
        .ok_or_else(|| ApiError::internal(format!("no free address on network {}", network.name)))
}

/// Give a container its addresses before its machine boots, and put it on
/// the switch.
pub(crate) async fn before_start(engine: &Arc<Engine>, c: &Arc<Container>) -> ApiResult<()> {
    let _lock = engine.networks.lock.lock().await;
    let record = c.record();
    let mut assigned: Vec<(String, EndpointRecord)> = Vec::new();
    for (name, mut ep) in ordered(&record) {
        let Some(network) = engine.networks.find(&name) else {
            return Err(ApiError::not_found(format!(
                "network {name} not found: it was removed while the container was stopped"
            )));
        };
        let ip = allocate(engine, &network, &ep.requested_ip, &record.id)?;
        let (_, len) = network.net().unwrap_or((Ipv4Addr::UNSPECIFIED, 16));
        ep.ip = ip.to_string();
        ep.prefix_len = len;
        ep.gateway = network.gateway.clone();
        ep.mac = mac_for(ip);
        ep.endpoint_id = super::util::new_id();
        ep.network_id = network.id.clone();
        assigned.push((name, ep));
    }
    c.update(engine, |r| {
        for (name, ep) in &assigned {
            r.networks.insert(name.clone(), ep.clone());
        }
    });
    let record = c.record();
    write_endpoint(engine, &record)?;
    link_all(engine, &record);
    Ok(())
}

/// Release a stopped container's addresses.
pub(crate) async fn after_stop(engine: &Arc<Engine>, c: &Arc<Container>) {
    let _lock = engine.networks.lock.lock().await;
    let record = c.record();
    unlink_all(engine, &record);
    c.update(engine, |r| {
        for ep in r.networks.values_mut() {
            ep.ip.clear();
            ep.prefix_len = 0;
            ep.gateway.clear();
            ep.endpoint_id.clear();
        }
    });
    let _ = std::fs::remove_file(
        engine
            .networks
            .switch_dir()
            .join("ep")
            .join(format!("{}.json", &record.id[..12])),
    );
}

/// Leave every network, as a container is removed.
pub(crate) async fn detach_all(engine: &Arc<Engine>, c: &Arc<Container>) {
    after_stop(engine, c).await;
}

fn mac_for(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    format!("02:42:{:02x}:{:02x}:{:02x}:{:02x}", o[0], o[1], o[2], o[3])
}

fn endpoint_socket(engine: &Engine, record: &ContainerRecord) -> PathBuf {
    engine
        .networks
        .switch_dir()
        .join("ep")
        .join(format!("{}.sock", &record.id[..12]))
}

fn write_endpoint(engine: &Engine, record: &ContainerRecord) -> ApiResult<()> {
    let members: Vec<smolvm_network::switch::Member> = ordered(record)
        .into_iter()
        .filter_map(|(name, ep)| {
            let network = engine.networks.find(&name)?;
            Some(smolvm_network::switch::Member {
                network: smolvm_network::switch::NetworkName::new(network.short())?,
                ip: ep.ip.parse().ok()?,
                prefix: ep.prefix_len,
            })
        })
        .collect();
    let path = engine
        .networks
        .switch_dir()
        .join("ep")
        .join(format!("{}.json", &record.id[..12]));
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, smolvm_network::switch::render_endpoint_file(&members))
        .and_then(|()| std::fs::rename(&tmp, &path))
        .map_err(|e| ApiError::internal(format!("write the container's switch endpoint: {e}")))
}

fn link_all(engine: &Engine, record: &ContainerRecord) {
    let socket = endpoint_socket(engine, record);
    for (name, ep) in &record.networks {
        if ep.ip.is_empty() {
            continue;
        }
        if let Some(network) = engine.networks.find(name) {
            let dir = engine.networks.switch_dir().join("n").join(network.short());
            let _ = std::fs::create_dir_all(&dir);
            let link = dir.join(&ep.ip);
            let _ = std::fs::remove_file(&link);
            let _ = std::os::unix::fs::symlink(&socket, &link);
        }
    }
}

fn unlink_all(engine: &Engine, record: &ContainerRecord) {
    let socket = endpoint_socket(engine, record);
    for (name, ep) in &record.networks {
        if ep.ip.is_empty() {
            continue;
        }
        if let Some(network) = engine.networks.find(name) {
            let link = engine
                .networks
                .switch_dir()
                .join("n")
                .join(network.short())
                .join(&ep.ip);
            // Only our own link: the address may be someone else's by now.
            if std::fs::read_link(&link).is_ok_and(|t| t == socket) {
                let _ = std::fs::remove_file(&link);
            }
        }
    }
}

/// `/etc/hosts` entries for the container beyond loopback: its own name at
/// its address, and its links.
pub(crate) fn hosts_entries(engine: &Engine, record: &ContainerRecord) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Some((_, ep)) = ordered(record).into_iter().next() {
        if !ep.ip.is_empty() {
            out.push((ep.ip.clone(), record.config.hostname.clone()));
        }
    }
    let mut links: Vec<String> = record.host_config.links.clone();
    for ep in record.networks.values() {
        links.extend(ep.links.iter().cloned());
    }
    for link in links {
        // `name:alias`, or Docker's own `/name:/self/alias`.
        let (target, alias) = link
            .split_once(':')
            .unwrap_or((link.as_str(), link.as_str()));
        let target = target.trim_start_matches('/');
        let alias = alias.rsplit('/').next().unwrap_or(alias);
        let Some(other) = engine.find_container(target) else {
            continue;
        };
        let other = other.record();
        let ip = record
            .networks
            .keys()
            .find_map(|n| other.networks.get(n).map(|ep| ep.ip.clone()))
            .filter(|ip| !ip.is_empty());
        if let Some(ip) = ip {
            out.push((ip, format!("{alias} {} {}", other.name, &other.id[..12])));
        }
    }
    out
}

/// What `host-gateway` in `--add-host` resolves to: the gateway, which a
/// container's stack answers for the host.
pub(crate) fn host_gateway(record: &ContainerRecord) -> String {
    ordered(record)
        .into_iter()
        .next()
        .map(|(_, ep)| ep.gateway)
        .filter(|g| !g.is_empty())
        .unwrap_or_else(|| "100.96.0.1".to_string())
}

/// `NetworkSettings` of inspect.
pub(crate) fn settings_view(record: &ContainerRecord, running: bool) -> serde_json::Value {
    let mut ports = serde_json::Map::new();
    if running {
        for key in record.config.exposed_ports.keys() {
            let (port, proto) = key.split_once('/').unwrap_or((key, "tcp"));
            let bindings: Vec<serde_json::Value> = record
                .ports
                .iter()
                .filter(|p| p.container_port.to_string() == port && p.proto == proto)
                .map(|p| {
                    serde_json::json!({"HostIp": p.host_ip, "HostPort": p.host_port.to_string()})
                })
                .collect();
            ports.insert(
                key.clone(),
                if bindings.is_empty() {
                    serde_json::Value::Null
                } else {
                    serde_json::Value::Array(bindings)
                },
            );
        }
    }
    let live = |s: &str| {
        if running {
            s.to_string()
        } else {
            String::new()
        }
    };
    let networks: serde_json::Map<String, serde_json::Value> = record
        .networks
        .iter()
        .map(|(name, ep)| {
            (
                name.clone(),
                serde_json::json!({
                    "IPAMConfig": if ep.requested_ip.is_empty() { serde_json::Value::Null } else { serde_json::json!({"IPv4Address": ep.requested_ip}) },
                    "Links": if ep.links.is_empty() { serde_json::Value::Null } else { serde_json::json!(ep.links) },
                    "Aliases": if ep.aliases.is_empty() { serde_json::Value::Null } else { serde_json::json!(ep.aliases) },
                    "MacAddress": live(&ep.mac),
                    "DriverOpts": null,
                    "GwPriority": 0,
                    "NetworkID": ep.network_id,
                    "EndpointID": live(&ep.endpoint_id),
                    "Gateway": live(&ep.gateway),
                    "IPAddress": live(&ep.ip),
                    "IPPrefixLen": if running { ep.prefix_len } else { 0 },
                    "IPv6Gateway": "",
                    "GlobalIPv6Address": "",
                    "GlobalIPv6PrefixLen": 0,
                    "DNSNames": null,
                }),
            )
        })
        .collect();
    let primary = ordered(record).into_iter().next().map(|(_, ep)| ep);
    let p =
        |f: fn(&EndpointRecord) -> &str| primary.as_ref().map(|e| live(f(e))).unwrap_or_default();
    serde_json::json!({
        "Bridge": "",
        "SandboxID": live(&record.machine),
        "SandboxKey": "",
        "HairpinMode": false,
        "LinkLocalIPv6Address": "",
        "LinkLocalIPv6PrefixLen": 0,
        "Ports": ports,
        "SecondaryIPAddresses": null,
        "SecondaryIPv6Addresses": null,
        "EndpointID": p(|e| &e.endpoint_id),
        "Gateway": p(|e| &e.gateway),
        "GlobalIPv6Address": "",
        "GlobalIPv6PrefixLen": 0,
        "IPAddress": p(|e| &e.ip),
        "IPPrefixLen": if running { primary.as_ref().map(|e| e.prefix_len).unwrap_or(0) } else { 0 },
        "IPv6Gateway": "",
        "MacAddress": p(|e| &e.mac),
        "Networks": networks,
    })
}

// ============================================================================
// API
// ============================================================================

type S = axum::extract::State<Arc<Engine>>;
type Q = axum::extract::Query<HashMap<String, String>>;
type P = axum::extract::Path<String>;

/// Network routes.
pub(crate) fn routes() -> axum::Router<Arc<Engine>> {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/networks", get(list))
        .route("/networks/create", post(create))
        .route("/networks/prune", post(prune))
        .route("/networks/{id}", get(inspect).delete(remove))
        .route("/networks/{id}/connect", post(connect))
        .route("/networks/{id}/disconnect", post(connect))
}

fn view(engine: &Engine, n: &NetworkRecord, with_containers: bool) -> serde_json::Value {
    let mut containers = serde_json::Map::new();
    if with_containers {
        for c in engine.containers.read().values() {
            let r = c.record();
            if let Some(ep) = r.networks.get(&n.name) {
                if ep.ip.is_empty() {
                    continue;
                }
                containers.insert(
                    r.id.clone(),
                    serde_json::json!({
                        "Name": r.name,
                        "EndpointID": ep.endpoint_id,
                        "MacAddress": ep.mac,
                        "IPv4Address": format!("{}/{}", ep.ip, ep.prefix_len),
                        "IPv6Address": "",
                    }),
                );
            }
        }
    }
    let config: Vec<serde_json::Value> = if n.subnet.is_empty() {
        Vec::new()
    } else {
        let mut c = serde_json::json!({"Subnet": n.subnet, "Gateway": n.gateway});
        if !n.ip_range.is_empty() {
            c["IPRange"] = serde_json::json!(n.ip_range);
        }
        vec![c]
    };
    serde_json::json!({
        "Name": n.name,
        "Id": n.id,
        "Created": n.created,
        "Scope": "local",
        "Driver": n.driver,
        "EnableIPv4": true,
        "EnableIPv6": false,
        "IPAM": {"Driver": "default", "Options": {}, "Config": config},
        "Internal": n.internal,
        "Attachable": n.attachable,
        "Ingress": false,
        "ConfigFrom": {"Network": ""},
        "ConfigOnly": false,
        "Containers": containers,
        "Options": n.options,
        "Labels": n.labels,
    })
}

fn in_use(engine: &Engine, n: &NetworkRecord) -> bool {
    engine
        .containers
        .read()
        .values()
        .any(|c| c.record().networks.contains_key(&n.name))
}

fn matches(engine: &Engine, n: &NetworkRecord, f: &Filters) -> bool {
    f.any("name", |v| n.name.contains(v))
        && f.any("id", |v| n.id.starts_with(v))
        && f.any("driver", |v| v == n.driver)
        && f.any("scope", |v| v == "local")
        && f.any("type", |v| (v == "builtin") == n.builtin)
        && f.any("dangling", |v| {
            (v == "true" || v == "1") == (!n.builtin && !in_use(engine, n))
        })
        && f.labels_match("label", &n.labels)
}

async fn list(
    axum::extract::State(engine): S,
    axum::extract::Query(q): Q,
) -> ApiResult<axum::Json<Vec<serde_json::Value>>> {
    let f = Filters::parse(q.get("filters").map(String::as_str)).map_err(ApiError::bad_request)?;
    let mut all = engine.networks.all();
    all.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(axum::Json(
        all.iter()
            .filter(|n| matches(&engine, n, &f))
            .map(|n| view(&engine, n, false))
            .collect(),
    ))
}

async fn inspect(
    axum::extract::State(engine): S,
    axum::extract::Path(id): P,
) -> ApiResult<axum::Json<serde_json::Value>> {
    let n = engine
        .networks
        .find(&id)
        .ok_or_else(|| ApiError::not_found(format!("network {id} not found")))?;
    Ok(axum::Json(view(&engine, &n, true)))
}

/// User-defined networks come later; the default ones cannot be created,
/// removed or changed.
const NO_USER_NETWORKS: &str =
    "user-defined networks are not supported yet: every container is on the default bridge network";

async fn create() -> ApiError {
    ApiError::not_implemented(NO_USER_NETWORKS)
}

async fn remove(
    axum::extract::State(engine): S,
    axum::extract::Path(id): P,
) -> ApiResult<axum::http::StatusCode> {
    let n = engine
        .networks
        .find(&id)
        .ok_or_else(|| ApiError::not_found(format!("network {id} not found")))?;
    Err(ApiError::new(
        axum::http::StatusCode::FORBIDDEN,
        format!("{} is a pre-defined network and cannot be removed", n.name),
    ))
}

async fn prune() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({"NetworksDeleted": []}))
}

async fn connect() -> ApiError {
    ApiError::not_implemented(NO_USER_NETWORKS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_mode_falls_back_to_the_default_network() {
        assert_eq!(mode_network(""), "bridge");
        assert_eq!(mode_network("host"), "bridge");
        assert_eq!(mode_network("proj_default"), "proj_default");
    }

    #[test]
    fn the_default_networks_are_there_once() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let socket = dir.path().join("run/docker.sock");
        let nets = Networks::load(&store, &socket).unwrap();
        let bridge = nets.find("bridge").unwrap();
        assert!(bridge.builtin);
        assert_eq!(bridge.subnet, "172.17.0.0/16");
        assert!(nets.find("host").is_some() && nets.find("none").is_some());
        let reloaded = Networks::load(&store, &socket).unwrap();
        assert_eq!(
            reloaded.all().iter().filter(|n| n.name == "bridge").count(),
            1
        );
    }
}
