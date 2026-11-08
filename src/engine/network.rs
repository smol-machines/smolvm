//! Container networks.
//!
//! Every container is its own machine with its own network stack on the
//! host, so a network between containers is not a bridge in one kernel: it
//! is the container switch ([`smolvm_network::switch`]), a directory this
//! module owns and every container's stack reads. A network is a subnet;
//! a container gets an address on each network it is on (the first one is
//! its interface's own address, the others are added to the interface while
//! it runs) and reaches the other containers on those networks, by address
//! and by name, and nothing else. Names are the container's name, its short
//! id and its aliases (Compose's service name among them), as Docker
//! resolves them; the default `bridge` network, as in Docker, resolves none.
//!
//! The engine writes, the stacks read:
//!
//! - `ep/<container>.json`: the container's addresses, primary first;
//! - `n/<network>/<address>`: a link to the container's endpoint socket,
//!   which is both its membership and its route;
//! - `n/<network>/names`: every name on the network and its address.
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
use super::model::{CreateRequest, EndpointSettings, NetworkCreateRequest};
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

fn overlaps(a: (Ipv4Addr, u8), b: (Ipv4Addr, u8)) -> bool {
    let len = a.1.min(b.1);
    u32::from(a.0) & mask(len) == u32::from(b.0) & mask(len)
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

    /// A subnet no network uses yet: Docker's pools, `172.18-31.0.0/16`
    /// then `192.168.N.0/20`.
    fn free_subnet(&self) -> Option<(Ipv4Addr, u8)> {
        let used: Vec<(Ipv4Addr, u8)> = self
            .records
            .read()
            .values()
            .filter_map(NetworkRecord::net)
            .collect();
        let candidates = (18..=31u8)
            .map(|b| (Ipv4Addr::new(172, b, 0, 0), 16))
            .chain((0..16u8).map(|n| (Ipv4Addr::new(192, 168, n * 16, 0), 20)));
        candidates
            .into_iter()
            .find(|c| !used.iter().any(|u| overlaps(*u, *c)))
    }

    fn create(&self, store: &Store, req: NetworkCreateRequest) -> ApiResult<NetworkRecord> {
        if req.name.is_empty() {
            return Err(ApiError::bad_request("network name is required"));
        }
        if self.find(&req.name).is_some_and(|r| r.name == req.name) {
            return Err(ApiError::conflict(format!(
                "network with name {} already exists",
                req.name
            )));
        }
        let driver = if req.driver.is_empty() {
            "bridge".to_string()
        } else {
            req.driver.clone()
        };
        if driver != "bridge" {
            return Err(ApiError::bad_request(format!(
                "network driver \"{driver}\" is not supported: every container is its own machine, and networks between them are bridge networks"
            )));
        }
        if req.enable_ipv6 == Some(true) {
            return Err(ApiError::bad_request(
                "IPv6 networks between containers are not supported yet",
            ));
        }
        let config = req
            .ipam
            .as_ref()
            .and_then(|i| {
                i.config
                    .iter()
                    .find(|c| !c.subnet.is_empty() && !c.subnet.contains(':'))
            })
            .cloned();
        let (net, len, gateway, ip_range) = match config {
            Some(c) => {
                let bad = || ApiError::bad_request(format!("invalid subnet {}", c.subnet));
                let (ip, len) = c.subnet.split_once('/').ok_or_else(bad)?;
                let ip: Ipv4Addr = ip.parse().map_err(|_| bad())?;
                let len: u8 = len
                    .parse()
                    .ok()
                    .filter(|l| (8..=30).contains(l))
                    .ok_or_else(|| {
                        ApiError::bad_request(format!(
                            "invalid subnet {}: the prefix must be between /8 and /30",
                            c.subnet
                        ))
                    })?;
                let net = Ipv4Addr::from(u32::from(ip) & mask(len));
                if self
                    .records
                    .read()
                    .values()
                    .filter_map(NetworkRecord::net)
                    .any(|u| overlaps(u, (net, len)))
                {
                    return Err(ApiError::bad_request(format!(
                        "invalid pool request: Pool overlaps with other one on this address space: {}",
                        c.subnet
                    )));
                }
                let first = Ipv4Addr::from(u32::from(net) + 1);
                if !c.gateway.is_empty() && c.gateway != first.to_string() {
                    return Err(ApiError::bad_request(format!(
                        "gateway {} is not supported: a network's gateway is the first address of its subnet ({first})",
                        c.gateway
                    )));
                }
                (net, len, first, c.ip_range.clone())
            }
            None => {
                let (net, len) = self
                    .free_subnet()
                    .ok_or_else(|| ApiError::internal("no free subnet for a new network"))?;
                (net, len, Ipv4Addr::from(u32::from(net) + 1), String::new())
            }
        };
        let record = NetworkRecord {
            id: super::util::new_id(),
            name: req.name.clone(),
            driver,
            created: super::util::now_rfc3339(),
            subnet: format!("{net}/{len}"),
            gateway: gateway.to_string(),
            ip_range,
            labels: req.labels.clone(),
            options: req.options.clone(),
            internal: req.internal,
            attachable: req.attachable,
            builtin: false,
        };
        store.save_object("networks", &record.id, &record)?;
        self.records
            .write()
            .insert(record.id.clone(), record.clone());
        let _ = std::fs::create_dir_all(self.dir.join("n").join(record.short()));
        Ok(record)
    }

    fn remove(&self, store: &Store, id: &str) {
        if let Some(r) = self.records.write().remove(id) {
            store.remove_object("networks", &r.id);
            let _ = std::fs::remove_dir_all(self.dir.join("n").join(r.short()));
        }
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

/// Whether every network of the container is internal (no way out).
pub(crate) fn internal_only(engine: &Engine, networks: &BTreeMap<String, EndpointRecord>) -> bool {
    !networks.is_empty()
        && networks
            .keys()
            .all(|n| engine.networks.find(n).is_some_and(|r| r.internal))
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
    refresh_names(
        engine,
        &assigned.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>(),
    );
    Ok(())
}

/// After the machine boots: put the container's other networks' addresses
/// on its interface.
pub(crate) async fn after_boot(socket: &Path, record: &ContainerRecord) -> ApiResult<()> {
    let extra = extra_addresses(record);
    if extra.is_empty() {
        return Ok(());
    }
    set_addresses(socket, extra).await
}

/// After a machine branched from a warm base boots: move its address, which
/// is still the base's, to its primary network, then add the others.
pub(crate) async fn after_branch(socket: &Path, record: &ContainerRecord) -> ApiResult<()> {
    if let Some((_, primary)) = ordered(record)
        .into_iter()
        .find(|(_, ep)| !ep.ip.is_empty())
    {
        let reply = super::runtime::request(
            socket,
            &smolvm_protocol::AgentRequest::SetPrimaryAddress {
                address: format!("{}/{}", primary.ip, primary.prefix_len),
                gateway: primary.gateway.clone(),
                dns: primary.gateway.clone(),
                dns_options: record.host_config.dns_options.clone(),
            },
        )
        .await
        .map_err(|e| ApiError::internal(format!("address the container: {e}")))?;
        if let Some(e) = super::runtime::error_text(&reply) {
            return Err(ApiError::internal(format!("address the container: {e}")));
        }
    }
    after_boot(socket, record).await
}

fn extra_addresses(record: &ContainerRecord) -> Vec<String> {
    ordered(record)
        .into_iter()
        .skip(1)
        .filter(|(_, ep)| !ep.ip.is_empty())
        .map(|(_, ep)| format!("{}/{}", ep.ip, ep.prefix_len))
        .collect()
}

async fn set_addresses(socket: &Path, addresses: Vec<String>) -> ApiResult<()> {
    let reply = super::runtime::request(
        socket,
        &smolvm_protocol::AgentRequest::SetInterfaceAddresses { addresses },
    )
    .await
    .map_err(|e| ApiError::internal(format!("configure the container's networks: {e}")))?;
    match super::runtime::error_text(&reply) {
        Some(e) => Err(ApiError::internal(format!(
            "configure the container's networks: {e}"
        ))),
        None => Ok(()),
    }
}

/// Release a stopped container's addresses.
pub(crate) async fn after_stop(engine: &Arc<Engine>, c: &Arc<Container>) {
    let _lock = engine.networks.lock.lock().await;
    let record = c.record();
    unlink_all(engine, &record);
    let names: Vec<String> = record.networks.keys().cloned().collect();
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
    refresh_names(engine, &names);
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

/// Rewrite the names files of `networks` from the running containers on them.
fn refresh_names(engine: &Engine, networks: &[String]) {
    let containers: Vec<ContainerRecord> = engine
        .containers
        .read()
        .values()
        .map(|c| c.record())
        .collect();
    for name in networks {
        let Some(network) = engine.networks.find(name) else {
            continue;
        };
        let mut text = String::new();
        // Docker's default network resolves no names.
        if !(network.builtin && network.name == "bridge") {
            for c in &containers {
                let Some(ep) = c.networks.get(&network.name) else {
                    continue;
                };
                if ep.ip.is_empty() {
                    continue;
                }
                for n in dns_names(c, ep) {
                    text.push_str(&format!("{n} {}\n", ep.ip));
                }
            }
        }
        let dir = engine.networks.switch_dir().join("n").join(network.short());
        let _ = std::fs::create_dir_all(&dir);
        let tmp = dir.join("names.tmp");
        if std::fs::write(&tmp, text).is_ok() {
            let _ = std::fs::rename(&tmp, dir.join("names"));
        }
    }
}

/// The names a container answers to on a network: its name, its short id,
/// and the endpoint's aliases.
fn dns_names(c: &ContainerRecord, ep: &EndpointRecord) -> Vec<String> {
    let mut names = vec![c.name.clone(), c.id[..12].to_string()];
    for a in &ep.aliases {
        if !names.contains(a) {
            names.push(a.clone());
        }
    }
    names
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
pub(crate) fn settings_view(
    engine: &Engine,
    record: &ContainerRecord,
    running: bool,
) -> serde_json::Value {
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
            let dns = engine
                .networks
                .find(name)
                .filter(|n| !(n.builtin && n.name == "bridge"))
                .map(|_| serde_json::json!(dns_names(record, ep)))
                .unwrap_or(serde_json::Value::Null);
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
                    "DNSNames": dns,
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
        .route("/networks/{id}/disconnect", post(disconnect))
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

fn network_event(engine: &Engine, action: &str, n: &NetworkRecord, container: Option<&str>) {
    let mut attrs = BTreeMap::from([
        ("name".to_string(), n.name.clone()),
        ("type".to_string(), n.driver.clone()),
    ]);
    if let Some(c) = container {
        attrs.insert("container".into(), c.to_string());
    }
    engine.events.emit("network", action, &n.id, attrs);
}

async fn create(
    axum::extract::State(engine): S,
    body: axum::body::Bytes,
) -> ApiResult<axum::response::Response> {
    use axum::response::IntoResponse;
    let req: NetworkCreateRequest = super::util::parse_body(&body)?;
    let record = {
        let _lock = engine.networks.lock.lock().await;
        engine.networks.create(&engine.store, req)?
    };
    network_event(&engine, "create", &record, None);
    Ok((
        axum::http::StatusCode::CREATED,
        axum::Json(serde_json::json!({"Id": record.id, "Warning": ""})),
    )
        .into_response())
}

async fn remove(
    axum::extract::State(engine): S,
    axum::extract::Path(id): P,
) -> ApiResult<axum::http::StatusCode> {
    let n = engine
        .networks
        .find(&id)
        .ok_or_else(|| ApiError::not_found(format!("network {id} not found")))?;
    if n.builtin {
        return Err(ApiError::new(
            axum::http::StatusCode::FORBIDDEN,
            format!("{} is a pre-defined network and cannot be removed", n.name),
        ));
    }
    let active = engine
        .containers
        .read()
        .values()
        .filter(|c| c.is_running())
        .any(|c| c.record().networks.contains_key(&n.name));
    if active {
        return Err(ApiError::new(
            axum::http::StatusCode::FORBIDDEN,
            format!(
                "error while removing network: network {} id {} has active endpoints",
                n.name, n.id
            ),
        ));
    }
    {
        let _lock = engine.networks.lock.lock().await;
        engine.networks.remove(&engine.store, &n.id);
    }
    network_event(&engine, "destroy", &n, None);
    Ok(axum::http::StatusCode::NO_CONTENT)
}

async fn prune(
    axum::extract::State(engine): S,
    axum::extract::Query(q): Q,
) -> ApiResult<axum::Json<serde_json::Value>> {
    let f = Filters::parse(q.get("filters").map(String::as_str)).map_err(ApiError::bad_request)?;
    let mut deleted = Vec::new();
    for n in engine.networks.all() {
        if n.builtin || !f.labels_match("label", &n.labels) || in_use(&engine, &n) {
            continue;
        }
        {
            let _lock = engine.networks.lock.lock().await;
            engine.networks.remove(&engine.store, &n.id);
        }
        network_event(&engine, "destroy", &n, None);
        deleted.push(n.name);
    }
    Ok(axum::Json(serde_json::json!({"NetworksDeleted": deleted})))
}

async fn connect(
    axum::extract::State(engine): S,
    axum::extract::Path(id): P,
    body: axum::body::Bytes,
) -> ApiResult<axum::http::StatusCode> {
    let req: super::model::NetworkConnectRequest = super::util::parse_body(&body)?;
    let n = engine
        .networks
        .find(&id)
        .ok_or_else(|| ApiError::not_found(format!("network {id} not found")))?;
    let c = engine
        .find_container(&req.container)
        .ok_or_else(|| ApiError::no_such_container(&req.container))?;
    let record = c.record();
    if record.networks.contains_key(&n.name) {
        return Err(ApiError::new(
            axum::http::StatusCode::FORBIDDEN,
            format!(
                "endpoint with name {} already exists in network {}",
                record.name, n.name
            ),
        ));
    }
    if record.host_config.network_mode == "none" || !n.routable() {
        return Err(ApiError::bad_request(format!(
            "container {} cannot be connected to network {}",
            record.name, n.name
        )));
    }
    let settings = req.endpoint_config.unwrap_or_default();
    let mut ep = endpoint_for(&n, &settings, &record.name);
    if c.is_running() {
        let record = {
            let _lock = engine.networks.lock.lock().await;
            let ip = allocate(&engine, &n, &ep.requested_ip, &record.id)?;
            let (_, len) = n.net().unwrap_or((Ipv4Addr::UNSPECIFIED, 16));
            ep.ip = ip.to_string();
            ep.prefix_len = len;
            ep.gateway = n.gateway.clone();
            ep.mac = mac_for(ip);
            ep.endpoint_id = super::util::new_id();
            c.update(&engine, |r| {
                r.networks.insert(n.name.clone(), ep.clone());
            });
            let record = c.record();
            write_endpoint(&engine, &record)?;
            link_all(&engine, &record);
            refresh_names(&engine, std::slice::from_ref(&n.name));
            record
        };
        if let Some(socket) = c.socket() {
            after_boot(&socket, &record).await?;
        }
    } else {
        c.update(&engine, |r| {
            r.networks.insert(n.name.clone(), ep.clone());
        });
    }
    network_event(&engine, "connect", &n, Some(&record.id));
    Ok(axum::http::StatusCode::OK)
}

async fn disconnect(
    axum::extract::State(engine): S,
    axum::extract::Path(id): P,
    body: axum::body::Bytes,
) -> ApiResult<axum::http::StatusCode> {
    let req: super::model::NetworkDisconnectRequest = super::util::parse_body(&body)?;
    let n = engine
        .networks
        .find(&id)
        .ok_or_else(|| ApiError::not_found(format!("network {id} not found")))?;
    let c = match engine.find_container(&req.container) {
        Some(c) => c,
        None if req.force => return Ok(axum::http::StatusCode::OK),
        None => return Err(ApiError::no_such_container(&req.container)),
    };
    let record = c.record();
    if !record.networks.contains_key(&n.name) {
        return Err(ApiError::new(
            axum::http::StatusCode::FORBIDDEN,
            format!(
                "container {} is not connected to network {}",
                record.id, n.name
            ),
        ));
    }
    {
        let _lock = engine.networks.lock.lock().await;
        unlink_all(&engine, &record);
        c.update(&engine, |r| {
            r.networks.remove(&n.name);
        });
        let record = c.record();
        if c.is_running() {
            write_endpoint(&engine, &record)?;
            link_all(&engine, &record);
        }
        refresh_names(&engine, std::slice::from_ref(&n.name));
    }
    if let Some(socket) = c.socket() {
        set_addresses(&socket, extra_addresses(&c.record())).await?;
    }
    network_event(&engine, "disconnect", &n, Some(&record.id));
    Ok(axum::http::StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subnets_overlap_by_the_shorter_prefix() {
        let a = (Ipv4Addr::new(172, 18, 0, 0), 16);
        assert!(overlaps(a, (Ipv4Addr::new(172, 18, 5, 0), 24)));
        assert!(!overlaps(a, (Ipv4Addr::new(172, 19, 0, 0), 16)));
    }

    #[test]
    fn host_mode_falls_back_to_the_default_network() {
        assert_eq!(mode_network(""), "bridge");
        assert_eq!(mode_network("host"), "bridge");
        assert_eq!(mode_network("proj_default"), "proj_default");
    }

    #[test]
    fn networks_get_docker_pools_and_refuse_overlaps() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let socket = dir.path().join("run/docker.sock");
        let nets = Networks::load(&store, &socket).unwrap();
        let req = |name: &str| NetworkCreateRequest {
            name: name.into(),
            ..Default::default()
        };
        let a = nets.create(&store, req("a")).unwrap();
        assert_eq!(a.subnet, "172.18.0.0/16");
        assert_eq!(a.gateway, "172.18.0.1");
        let b = nets.create(&store, req("b")).unwrap();
        assert_eq!(b.subnet, "172.19.0.0/16");
        assert!(nets.create(&store, req("a")).is_err());
        let mut custom = req("c");
        custom.ipam = Some(super::super::model::Ipam {
            driver: String::new(),
            config: vec![super::super::model::IpamConfig {
                subnet: "172.18.4.0/24".into(),
                ..Default::default()
            }],
        });
        assert!(nets.create(&store, custom).is_err());
        assert!(nets.find("bridge").unwrap().builtin);
        let reloaded = Networks::load(&store, &socket).unwrap();
        assert!(reloaded.find("a").is_some());
        assert_eq!(
            reloaded.all().iter().filter(|n| n.name == "bridge").count(),
            1
        );
    }
}
