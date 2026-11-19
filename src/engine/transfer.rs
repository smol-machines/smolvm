//! Dependency preflight for a complete workload move.
//!
//! This endpoint never pauses machines or authorizes a move. Its closure tells
//! the coordinator which containers must share a transfer boundary; the caller
//! must explicitly select additional containers, establish durable admission
//! fences, revalidate the plan and then pause *all* writers before copying data.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::containers::ContainerRecord;
use super::images::ImageRecord;
use super::network::NetworkRecord;
use super::util::{ApiError, ApiResult};
use super::volumes::VolumeRecord;
use super::Engine;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PlanRequest {
    containers: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Plan {
    /// Preflight is not a claim that the destination supports this workload.
    phase: &'static str,
    selected: Vec<String>,
    members: Vec<Member>,
    additional_containers: Vec<String>,
    machines: Vec<String>,
    images: Vec<String>,
    volumes: Vec<String>,
    networks: Vec<String>,
    dependencies: BTreeSet<Dependency>,
    blockers: BTreeSet<Blocker>,
    /// Binds configuration and execution lineage without returning secrets.
    fingerprint: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Member {
    id: String,
    name: String,
    machine: String,
    selected: bool,
}

#[derive(Serialize, PartialEq, Eq, PartialOrd, Ord)]
struct Dependency {
    kind: &'static str,
    resource: String,
    containers: Vec<String>,
}

#[derive(Serialize, PartialEq, Eq, PartialOrd, Ord)]
struct Blocker {
    code: &'static str,
    container: String,
    resource: String,
}

pub(super) async fn plan(
    State(engine): State<Arc<Engine>>,
    Json(request): Json<PlanRequest>,
) -> ApiResult<Json<Plan>> {
    if request.containers.is_empty() || request.containers.len() > 1024 {
        return Err(ApiError::bad_request(
            "select between 1 and 1024 containers",
        ));
    }
    tokio::task::spawn_blocking(move || build(&engine, &request.containers))
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
        .map(Json)
}

fn resolve<'a>(records: &'a BTreeMap<String, ContainerRecord>, name: &str) -> ApiResult<&'a str> {
    let name = name.trim_start_matches('/');
    if let Some(record) = records.get(name) {
        return Ok(&record.id);
    }
    let named: Vec<_> = records.values().filter(|r| r.name == name).collect();
    if named.len() == 1 {
        return Ok(&named[0].id);
    }
    if named.len() > 1 {
        return Err(ApiError::conflict(
            "duplicate container names prevent transfer planning",
        ));
    }
    let matches: Vec<_> = records
        .keys()
        .filter(|id| !name.is_empty() && id.starts_with(name))
        .collect();
    match matches.as_slice() {
        [id] => Ok(id),
        [] => Err(ApiError::no_such_container(name)),
        _ => Err(ApiError::bad_request(format!(
            "container prefix {name} is ambiguous"
        ))),
    }
}

pub(super) fn machine_owner<'a>(
    records: &'a BTreeMap<String, ContainerRecord>,
    id: &'a str,
) -> ApiResult<&'a str> {
    let mut id = id;
    let mut visited = BTreeSet::new();
    loop {
        if !visited.insert(id) {
            return Err(ApiError::conflict(
                "container machine-sharing cycle prevents transfer planning",
            ));
        }
        let record = &records[id];
        match record.network_host() {
            Some(host) => id = resolve(records, host)?,
            None => return Ok(id),
        }
    }
}

#[derive(Serialize)]
struct LiveShare {
    name: String,
    source: PathBuf,
    read_only: bool,
}

fn live_shares(name: &str, deadline: Instant) -> crate::Result<Vec<LiveShare>> {
    let mut shares = Vec::new();
    for read_only in [false, true] {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| {
                crate::Error::agent("plan transfer", "live share inventory timed out")
            })?;
        for (name, source) in
            crate::attach::shared_directories_with_timeout(name, read_only, remaining)?
        {
            shares.push(LiveShare {
                name,
                source,
                read_only,
            });
        }
    }
    Ok(shares)
}

fn build(engine: &Engine, requested: &[String]) -> ApiResult<Plan> {
    build_with_inventory(engine, requested, live_shares)
}

fn build_with_inventory(
    engine: &Engine,
    requested: &[String],
    mut inventory: impl FnMut(&str, Instant) -> crate::Result<Vec<LiveShare>>,
) -> ApiResult<Plan> {
    let records: BTreeMap<_, _> = engine
        .store
        .transfer_containers()?
        .into_iter()
        .map(|r| (r.id.clone(), r))
        .collect();
    let mut volumes = BTreeMap::new();
    for (key, record) in engine.store.transfer_objects::<VolumeRecord>("volumes")? {
        if key != record.name || !super::volumes::valid_volume_name(&key) {
            return Err(ApiError::conflict("volume record identity is invalid"));
        }
        volumes.insert(key, record);
    }
    let mut networks = BTreeMap::new();
    for (key, record) in engine.store.transfer_objects::<NetworkRecord>("networks")? {
        if key != record.id || !super::store::valid_id(&key) {
            return Err(ApiError::conflict("network record identity is invalid"));
        }
        networks.insert(key, record);
    }
    let selected = requested
        .iter()
        .map(|id| resolve(&records, id).map(str::to_owned))
        .collect::<ApiResult<BTreeSet<_>>>()?;
    let mut groups = BTreeMap::<(&'static str, String), BTreeSet<String>>::new();
    let mut owners = BTreeMap::new();
    for (id, record) in &records {
        let owner = machine_owner(&records, id)?;
        owners.insert(id.clone(), owner.to_owned());
        groups
            .entry(("machine", records[owner].machine.clone()))
            .or_default()
            .insert(id.clone());
        for mount in &record.mounts {
            if mount.kind == "volume" {
                if !volumes.contains_key(&mount.source) {
                    return Err(ApiError::conflict(format!(
                        "container {} references missing volume {}",
                        record.name, mount.source
                    )));
                }
                // Include readers too: leaving them behind would split one
                // shared volume into two independent views after a move.
                groups
                    .entry(("volume", mount.source.clone()))
                    .or_default()
                    .insert(id.clone());
            }
        }
        for endpoint in record.networks.values() {
            let network = networks.get(&endpoint.network_id).ok_or_else(|| {
                ApiError::conflict(format!(
                    "container {} references a missing network",
                    record.name
                ))
            })?;
            if !network.builtin {
                groups
                    .entry(("network", network.id.clone()))
                    .or_default()
                    .insert(id.clone());
            }
        }
        for link in &record.host_config.links {
            let target = resolve(&records, link.split(':').next().unwrap_or(link))?;
            groups
                .entry(("link", format!("{id}:{target}")))
                .or_default()
                .extend([id.clone(), target.to_owned()]);
        }
    }
    let mut members = selected.clone();
    loop {
        let before = members.len();
        for ids in groups.values() {
            if !ids.is_disjoint(&members) {
                members.extend(ids.iter().cloned());
            }
        }
        if members.len() == before {
            break;
        }
    }
    let mut blockers = BTreeSet::new();
    // Read the exact image IDs the selected closure uses, never resolve mutable
    // tags again. Unrelated images are not dependencies of this move.
    let mut images = BTreeMap::<String, ImageRecord>::new();
    for id in &members {
        let image_id = &records[id].image_id;
        if images.contains_key(image_id) {
            continue;
        }
        let key = image_id
            .strip_prefix("sha256:")
            .filter(|key| super::store::valid_id(key))
            .ok_or_else(|| ApiError::conflict("container image identity is invalid"))?;
        let image: ImageRecord = engine.store.transfer_object("images", key).map_err(|_| {
            ApiError::conflict(format!("image {image_id} is unavailable for transfer"))
        })?;
        if image.id != *image_id {
            return Err(ApiError::conflict("image record identity is invalid"));
        }
        images.insert(image_id.clone(), image);
    }
    let mut dependencies = BTreeSet::new();
    let mut volume_names = BTreeSet::new();
    let mut network_ids = BTreeSet::new();
    for ((kind, resource), ids) in &groups {
        if ids.is_disjoint(&members) {
            continue;
        }
        if *kind == "volume" {
            volume_names.insert(resource.clone());
        }
        if *kind == "network" {
            network_ids.insert(resource.clone());
        }
        if ids.len() > 1 {
            dependencies.insert(Dependency {
                kind,
                resource: resource.clone(),
                containers: ids.iter().cloned().collect(),
            });
        }
    }
    let machines: BTreeSet<_> = members
        .iter()
        .map(|id| records[&owners[id]].machine.clone())
        .collect();
    let mut roots = Vec::new();
    for name in &volume_names {
        if !volumes[name].options.is_empty() {
            blockers.insert(Blocker {
                code: "volume_driver_options",
                container: String::new(),
                resource: name.clone(),
            });
        }
        let root = engine.volumes.mountpoint(name);
        // Engine-managed directories cannot secretly refer to another host
        // path. A host bind mount is handled as an explicit unsupported input.
        let parent = root.parent().unwrap();
        if !std::fs::symlink_metadata(parent).is_ok_and(|m| m.is_dir())
            || !std::fs::symlink_metadata(&root).is_ok_and(|m| m.is_dir())
        {
            return Err(ApiError::conflict(format!(
                "volume {name} is not an ordinary managed directory"
            )));
        }
        let canonical =
            std::fs::canonicalize(root).map_err(|e| ApiError::internal(e.to_string()))?;
        let expected = std::fs::canonicalize(engine.store.root())
            .map_err(|e| ApiError::internal(e.to_string()))?
            .join("volumes")
            .join(name)
            .join("_data");
        if canonical != expected {
            return Err(ApiError::conflict(format!(
                "volume {name} escapes its managed location"
            )));
        }
        roots.push((name, canonical));
    }
    for id in &members {
        let record = &records[id];
        for mount in &record.mounts {
            if mount.socket || !matches!(mount.kind.as_str(), "volume" | "tmpfs") {
                blockers.insert(Blocker {
                    code: if mount.socket {
                        "host_socket"
                    } else {
                        "host_bind_mount"
                    },
                    container: id.clone(),
                    resource: mount.destination.clone(),
                });
            }
        }
        if !record.pending_archives.is_empty() {
            blockers.insert(Blocker {
                code: "pending_file_uploads",
                container: id.clone(),
                resource: record.name.clone(),
            });
        }
    }
    let vms = engine.db.list_vms()?;
    let selected_owners: BTreeSet<_> = members.iter().map(|id| &owners[id]).collect();
    for owner in selected_owners {
        let record = &records[owner];
        match vms.iter().find(|(name, _)| name == &record.machine) {
            Some((name, vm)) => {
                if vm.labels.get(super::containers::MACHINE_LABEL) != Some(owner) {
                    blockers.insert(Blocker {
                        code: "machine_ownership_mismatch",
                        container: owner.clone(),
                        resource: name.clone(),
                    });
                }
                for mount in vm.host_mounts() {
                    let source = std::fs::canonicalize(&mount.source).ok();
                    if !source.is_some_and(|source| roots.iter().any(|(_, root)| root == &source)) {
                        blockers.insert(Blocker {
                            code: "untracked_machine_mount",
                            container: owner.clone(),
                            resource: mount.target.display().to_string(),
                        });
                    }
                    if mount.staged || mount.owner.is_some() || !mount.recorded_ownership {
                        blockers.insert(Blocker {
                            code: "unsupported_mount_policy",
                            container: owner.clone(),
                            resource: mount.target.display().to_string(),
                        });
                    }
                }
            }
            None if matches!(
                record.state.status.as_str(),
                "running" | "paused" | "restarting"
            ) =>
            {
                blockers.insert(Blocker {
                    code: "missing_machine",
                    container: owner.clone(),
                    resource: record.machine.clone(),
                });
            }
            None => {}
        }
    }
    for (name, vm) in &vms {
        if machines.contains(name) {
            continue;
        }
        for mount in vm.host_mounts() {
            let source = match std::fs::canonicalize(&mount.source) {
                Ok(path) => path,
                Err(_) if roots.is_empty() => continue,
                Err(_) => {
                    blockers.insert(Blocker {
                        code: "unresolved_machine_mount",
                        container: String::new(),
                        resource: name.clone(),
                    });
                    continue;
                }
            };
            for (volume, root) in &roots {
                if overlaps(&source, root) {
                    blockers.insert(Blocker {
                        code: "external_machine_volume_user",
                        container: String::new(),
                        resource: format!("{name}:{volume}"),
                    });
                }
            }
        }
    }
    // Dynamic SHARE_ADD exports are absent from VmRecord. Ask the VMM, not
    // just the guest's attached-mount list: sidecar/image exports can exist
    // without a guest mount-list entry. Observing never starts a machine.
    // This is still a preflight, not an atomic inventory or admission fence.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut live_identities = Vec::new();
    for (name, vm) in &vms {
        let selected = machines.contains(name);
        if !selected && roots.is_empty() {
            continue;
        }
        if !vm.is_process_alive() {
            if vm.paused_checkpoint.is_some() {
                // The checkpoint can retain dynamic exports we cannot inspect
                // through a stopped VMM. Do not infer absence from its record.
                blockers.insert(Blocker {
                    code: "saved_machine_shares_unverified",
                    container: String::new(),
                    resource: name.clone(),
                });
            }
            continue;
        }
        let shares = match inventory(name, deadline) {
            Ok(shares) => shares,
            Err(_) => {
                blockers.insert(Blocker {
                    code: "live_machine_shares_unverified",
                    container: String::new(),
                    resource: name.clone(),
                });
                continue;
            }
        };
        if selected {
            live_identities.push(serde_json::json!({"machine":name,"pid":vm.pid,"startTime":vm.pid_start_time,"shares":shares}));
        }
        for share in shares {
            let source = match std::fs::canonicalize(&share.source) {
                Ok(source) => source,
                Err(_) => {
                    blockers.insert(Blocker {
                        code: "unresolved_live_share",
                        container: String::new(),
                        resource: format!("{name}:{}", share.name),
                    });
                    continue;
                }
            };
            if selected {
                // Boot-mount relocation does not yet relocate live device
                // exports. Keep them visible as a bundle requirement, even
                // when their data is an already selected managed volume.
                blockers.insert(Blocker {
                    code: "live_share_relocation_required",
                    container: String::new(),
                    resource: format!("{name}:{}", share.name),
                });
            } else {
                for (volume, root) in &roots {
                    if overlaps(&source, root) {
                        blockers.insert(Blocker {
                            code: "external_live_volume_user",
                            container: String::new(),
                            resource: format!("{name}:{volume}"),
                        });
                        live_identities.push(serde_json::json!({"machine":name,"pid":vm.pid,"startTime":vm.pid_start_time,"share":share,"source":source}));
                    }
                }
            }
        }
    }
    // Hash only the relevant closure. Starting an unrelated container must
    // not invalidate the user's plan. Status/health polling is also irrelevant;
    // configuration changes and a new execution generation are not.
    let mut identities = Vec::new();
    for id in &members {
        let mut value =
            serde_json::to_value(&records[id]).map_err(|e| ApiError::internal(e.to_string()))?;
        let object = value.as_object_mut().unwrap();
        for field in [
            "state",
            "agent_socket",
            "restart_count",
            "running_at_shutdown",
            "saved_execution",
            "execution_suspended",
        ] {
            object.remove(field);
        }
        identities.push(value);
    }
    let machine_identities = vms
        .iter()
        .filter(|(name, _)| machines.contains(name))
        .map(|(name, vm)| {
            if vm.name != *name {
                return Err(ApiError::conflict("machine record identity is invalid"));
            }
            let identity = vm.database_identity.as_ref().ok_or_else(|| {
                ApiError::conflict(
                    "machine identity is missing or corrupt; recover it before moving",
                )
            })?;
            // list_vms read this generation and configuration atomically. A
            // second name lookup could accidentally bind an older config to a
            // replacement's identity. Hash secrets; do not return them.
            Ok(serde_json::json!({"name":name,"generation":identity.generation(),"config":vm}))
        })
        .collect::<ApiResult<Vec<_>>>()?;
    use std::os::unix::fs::MetadataExt;
    let volume_identities = roots.iter().map(|(name, root)| {
        let metadata = std::fs::metadata(root).map_err(|e| ApiError::internal(e.to_string()))?;
        Ok(serde_json::json!({"name":name,"path":root,"device":metadata.dev(),"inode":metadata.ino()}))
    }).collect::<ApiResult<Vec<_>>>()?;
    let data = serde_json::to_vec(&serde_json::json!({
        "version":3,"selected":selected,"containers":identities,"images":images.values().collect::<Vec<_>>(),
        "volumes":volume_names.iter().map(|name|&volumes[name]).collect::<Vec<_>>(),
        "networks":network_ids.iter().map(|id|&networks[id]).collect::<Vec<_>>(),
        "machines":machine_identities,"volumeIdentities":volume_identities,"liveShares":live_identities,"blockers":blockers,
    }))
    .map_err(|e| ApiError::internal(e.to_string()))?;
    let fingerprint = format!("sha256:{:x}", Sha256::digest(data));
    Ok(Plan {
        phase: "preflight_only",
        selected: selected.iter().cloned().collect(),
        members: members
            .iter()
            .map(|id| Member {
                id: id.clone(),
                name: records[id].name.clone(),
                machine: records[&owners[id]].machine.clone(),
                selected: selected.contains(id),
            })
            .collect(),
        additional_containers: members.difference(&selected).cloned().collect(),
        machines: machines.into_iter().collect(),
        images: images.into_keys().collect(),
        volumes: volume_names.into_iter().collect(),
        networks: network_ids.into_iter().collect(),
        dependencies,
        blockers,
        fingerprint,
    })
}

fn overlaps(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}

#[cfg(test)]
mod tests {
    use super::super::containers::{MountRecord, StateRecord};
    use super::*;

    fn record(engine: &Engine, byte: char, name: &str, volume: Option<&str>) -> ContainerRecord {
        let image = image_record('e');
        if !engine.store.object_path("images", &"e".repeat(64)).exists() {
            engine
                .store
                .save_object("images", &"e".repeat(64), &image)
                .unwrap();
        }
        let mut record:ContainerRecord=serde_json::from_value(serde_json::json!({
            "id":byte.to_string().repeat(64),"name":name,"created":"","image":"example","image_id":image.id,
            "pull_ref":image.pull_ref,"machine":format!("vm-{name}"),"config":{},"host_config":{},"host_config_raw":{},
            "networks":{},"path":"sh","args":[],"state":StateRecord::default(),"restart_count":0,"ports":[],"mounts":[]
        })).unwrap();
        if let Some(volume) = volume {
            engine
                .volumes
                .create(
                    &engine.store,
                    Some(volume),
                    BTreeMap::new(),
                    BTreeMap::new(),
                    false,
                )
                .unwrap();
            record.mounts.push(MountRecord {
                kind: "volume".into(),
                source: volume.into(),
                destination: "/data".into(),
                read_only: false,
                share: Some(0),
                subpath: None,
                mode: String::new(),
                options: vec![],
                copy_up: false,
                socket: false,
            });
        }
        engine.store.save_container(&record).unwrap();
        record
    }

    fn image_record(byte: char) -> super::super::images::ImageRecord {
        let digest = format!("sha256:{}", byte.to_string().repeat(64));
        super::super::images::ImageRecord {
            id: digest.clone(),
            repo_tags: vec!["example:latest".into()],
            repo_digests: vec![format!("example@{digest}")],
            pull_ref: format!("example@{digest}"),
            config: serde_json::json!({"architecture":"arm64","os":"linux","config":{"Env":["TOKEN=image-fixture-secret"]}}),
            size: 123,
            pulled: String::new(),
            last_tag_time: String::new(),
        }
    }

    #[test]
    fn transfer_preflight_binds_selected_image_metadata_without_returning_secrets() {
        let root = tempfile::tempdir().unwrap();
        let engine = super::super::test_engine(root.path());
        record(&engine, 'a', "web", None);
        let first = build(&engine, &["web".into()]).unwrap();
        assert_eq!(first.images, vec![image_record('e').id]);
        engine
            .store
            .save_object("images", &"f".repeat(64), &image_record('f'))
            .unwrap();
        assert_eq!(
            first.fingerprint,
            build(&engine, &["web".into()]).unwrap().fingerprint
        );
        std::fs::write(engine.store.object_path("images", &"f".repeat(64)), b"{").unwrap();
        assert_eq!(
            first.fingerprint,
            build(&engine, &["web".into()]).unwrap().fingerprint
        );
        let mut image = image_record('e');
        image.repo_tags.push("example:retained".into());
        engine
            .store
            .save_object("images", &"e".repeat(64), &image)
            .unwrap();
        let changed = build(&engine, &["web".into()]).unwrap();
        assert_ne!(first.fingerprint, changed.fingerprint);
        assert!(!serde_json::to_string(&changed)
            .unwrap()
            .contains("image-fixture-secret"));
        let path = engine.store.object_path("images", &"e".repeat(64));
        std::fs::remove_file(&path).unwrap();
        assert!(build(&engine, &["web".into()]).is_err());
        engine
            .store
            .save_object("images", &"e".repeat(64), &image_record('f'))
            .unwrap();
        assert!(build(&engine, &["web".into()]).is_err());
        engine
            .store
            .save_object("images", &"e".repeat(64), &image)
            .unwrap();
        let retained = root.path().join("retained-image.json");
        std::fs::rename(&path, &retained).unwrap();
        std::os::unix::fs::symlink(&retained, &path).unwrap();
        assert!(build(&engine, &["web".into()]).is_err());
    }

    #[test]
    fn transfer_preflight_binds_machine_recreation_and_configuration() {
        let root = tempfile::tempdir().unwrap();
        let engine = super::super::test_engine(root.path());
        let a = record(&engine, 'a', "web", None);
        let mut vm = crate::config::VmRecord::new(a.machine.clone(), 1, 128, vec![], vec![], false);
        vm.labels
            .insert(super::super::containers::MACHINE_LABEL.into(), a.id.clone());
        vm.env
            .push(("TOKEN".into(), "machine-fixture-secret".into()));
        engine.db.insert_vm(&a.machine, &vm).unwrap();
        let first = build(&engine, &["web".into()]).unwrap();
        engine.db.remove_vm(&a.machine).unwrap();
        engine.db.insert_vm(&a.machine, &vm).unwrap();
        let replaced = build(&engine, &["web".into()]).unwrap();
        assert_ne!(first.fingerprint, replaced.fingerprint);
        engine.db.update_vm(&a.machine, |vm| vm.mem = 256).unwrap();
        let changed = build(&engine, &["web".into()]).unwrap();
        assert_ne!(replaced.fingerprint, changed.fingerprint);
        assert!(!serde_json::to_string(&changed)
            .unwrap()
            .contains("machine-fixture-secret"));
        let connection = rusqlite::Connection::open(root.path().join("test.db")).unwrap();
        connection
            .execute("DELETE FROM vm_incarnations WHERE name = ?1", [&a.machine])
            .unwrap();
        assert!(build(&engine, &["web".into()]).is_err());
    }

    #[test]
    fn transfer_preflight_closes_transitive_volume_and_machine_dependencies_without_mutation() {
        let root = tempfile::tempdir().unwrap();
        let engine = super::super::test_engine(root.path());
        let a = record(&engine, 'a', "web", Some("data"));
        let mut b = record(&engine, 'b', "reader", Some("data"));
        b.mounts[0].read_only = true;
        engine.store.save_container(&b).unwrap();
        let mut c = record(&engine, 'c', "sidecar", None);
        c.host_config.network_mode = "container:reader".into();
        engine.store.save_container(&c).unwrap();
        let paths = [&a, &b, &c].map(|r| engine.store.container_dir(&r.id).join("config.json"));
        let before = paths.each_ref().map(|p| std::fs::read(p).unwrap());
        let plan = build(&engine, &["web".into()]).unwrap();
        assert_eq!(plan.additional_containers, vec![b.id, c.id]);
        assert_eq!(plan.machines, vec!["vm-reader", "vm-web"]);
        assert_eq!(plan.volumes, vec!["data"]);
        assert!(plan.blockers.is_empty());
        assert_eq!(plan.phase, "preflight_only");
        assert_eq!(before, paths.each_ref().map(|p| std::fs::read(p).unwrap()));
        assert!(engine.db.list_vms().unwrap().is_empty());
    }

    #[test]
    fn transfer_preflight_refuses_unreadable_missing_and_misidentified_records() {
        let root = tempfile::tempdir().unwrap();
        let engine = super::super::test_engine(root.path());
        record(&engine, 'a', "web", Some("data"));
        let b = record(&engine, 'b', "hidden-writer", Some("data"));
        let path = engine.store.container_dir(&b.id).join("config.json");
        let good = std::fs::read(&path).unwrap();
        std::fs::write(&path, b"{").unwrap();
        assert!(build(&engine, &["web".into()]).is_err());
        std::fs::remove_file(&path).unwrap();
        assert!(build(&engine, &["web".into()]).is_err());
        std::fs::write(&path, &good).unwrap();
        let mut renamed = b;
        renamed.id = "c".repeat(64);
        std::fs::write(&path, serde_json::to_vec(&renamed).unwrap()).unwrap();
        assert!(build(&engine, &["web".into()]).is_err());
        std::fs::write(path, good).unwrap();
        std::fs::remove_file(engine.store.object_path("volumes", "data")).unwrap();
        assert!(build(&engine, &["web".into()]).is_err());
    }

    #[test]
    fn transfer_preflight_hash_tracks_configuration_and_dependencies_without_returning_secrets() {
        let root = tempfile::tempdir().unwrap();
        let engine = super::super::test_engine(root.path());
        let mut a = record(&engine, 'a', "web", Some("data"));
        a.config.env = vec!["TOKEN=fixture-secret".into()];
        engine.store.save_container(&a).unwrap();
        let first = build(&engine, &["web".into()]).unwrap();
        assert!(!serde_json::to_string(&first)
            .unwrap()
            .contains("fixture-secret"));
        a.state.pid = 123;
        a.state.error = "updated status detail".into();
        engine.store.save_container(&a).unwrap();
        record(&engine, 'b', "unrelated", None);
        assert_eq!(
            first.fingerprint,
            build(&engine, &["web".into()]).unwrap().fingerprint
        );
        a.execution_generation += 1;
        engine.store.save_container(&a).unwrap();
        let second = build(&engine, &["web".into()]).unwrap();
        assert_ne!(first.fingerprint, second.fingerprint);
        record(&engine, 'c', "new-reader", Some("data"));
        assert_ne!(
            second.fingerprint,
            build(&engine, &["web".into()]).unwrap().fingerprint
        );
    }

    #[test]
    fn transfer_preflight_refuses_machine_cycles_and_reports_host_dependencies() {
        let root = tempfile::tempdir().unwrap();
        let engine = super::super::test_engine(root.path());
        let mut a = record(&engine, 'a', "web", Some("data"));
        let mut b = record(&engine, 'b', "sidecar", None);
        a.host_config.network_mode = "container:sidecar".into();
        b.host_config.network_mode = "container:web".into();
        engine.store.save_container(&a).unwrap();
        engine.store.save_container(&b).unwrap();
        assert!(build(&engine, &["web".into()]).is_err());
        a.host_config.network_mode = String::new();
        a.mounts[0].kind = "bind".into();
        engine.store.save_container(&a).unwrap();
        let plan = build(&engine, &["web".into()]).unwrap();
        assert!(plan.blockers.iter().any(|b| b.code == "host_bind_mount"));
    }

    #[test]
    fn transfer_preflight_keeps_private_service_networks_together_but_not_default_bridge_peers() {
        let root = tempfile::tempdir().unwrap();
        let engine = super::super::test_engine(root.path());
        let mut a = record(&engine, 'a', "web", None);
        let mut b = record(&engine, 'b', "database", None);
        let mut c = record(&engine, 'c', "unrelated", None);
        let network:NetworkRecord=serde_json::from_value(serde_json::json!({"id":"d".repeat(64),"name":"project_default","driver":"bridge","created":"","subnet":"172.20.0.0/16","gateway":"172.20.0.1"})).unwrap();
        engine
            .store
            .save_object("networks", &network.id, &network)
            .unwrap();
        for r in [&mut a, &mut b] {
            r.networks.insert(
                network.id.clone(),
                super::super::containers::EndpointRecord {
                    network_id: network.id.clone(),
                    ..Default::default()
                },
            );
            engine.store.save_container(r).unwrap();
        }
        let bridge = engine
            .networks
            .all()
            .into_iter()
            .find(|n| n.name == "bridge")
            .unwrap();
        for r in [&mut a, &mut c] {
            r.networks.insert(
                bridge.id.clone(),
                super::super::containers::EndpointRecord {
                    network_id: bridge.id.clone(),
                    ..Default::default()
                },
            );
            engine.store.save_container(r).unwrap();
        }
        let plan = build(&engine, &["web".into()]).unwrap();
        assert_eq!(plan.additional_containers, vec![b.id]);
        assert_eq!(plan.networks, vec![network.id]);
    }

    #[test]
    fn transfer_preflight_finds_machine_aliases_of_a_volume_and_rejects_symlinked_storage() {
        let root = tempfile::tempdir().unwrap();
        let engine = super::super::test_engine(root.path());
        record(&engine, 'a', "web", Some("data"));
        let alias = root.path().join("alias");
        std::os::unix::fs::symlink(engine.volumes.mountpoint("data"), &alias).unwrap();
        let mut vm = crate::config::VmRecord::new("outside".into(), 1, 512, vec![], vec![], false);
        vm.mounts = vec![(
            alias.to_string_lossy().into_owned(),
            "/outside".into(),
            false,
        )];
        engine.db.insert_vm("outside", &vm).unwrap();
        let plan = build(&engine, &["web".into()]).unwrap();
        assert!(plan
            .blockers
            .iter()
            .any(|b| b.code == "external_machine_volume_user"));
        engine.db.remove_vm("outside").unwrap();
        let data = engine.volumes.mountpoint("data");
        let elsewhere = root.path().join("elsewhere");
        std::fs::rename(&data, &elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &data).unwrap();
        assert!(build(&engine, &["web".into()]).is_err());
    }

    #[test]
    fn transfer_preflight_rejects_indirect_and_special_record_files() {
        let root = tempfile::tempdir().unwrap();
        let engine = super::super::test_engine(root.path());
        let a = record(&engine, 'a', "web", None);
        let path = engine.store.container_dir(&a.id).join("config.json");
        let saved = root.path().join("saved.json");
        std::fs::rename(&path, &saved).unwrap();
        std::os::unix::fs::symlink(&saved, &path).unwrap();
        assert!(build(&engine, &["web".into()]).is_err());
        std::fs::remove_file(&path).unwrap();
        use std::os::unix::ffi::OsStrExt;
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // A damaged record must fail rather than block waiting for a FIFO writer.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(build(&engine, &["web".into()]).is_err());
    }

    #[test]
    fn transfer_preflight_binds_volume_identity_and_reports_machine_ownership_conflicts() {
        let root = tempfile::tempdir().unwrap();
        let engine = super::super::test_engine(root.path());
        let a = record(&engine, 'a', "web", Some("data"));
        let first = build(&engine, &["web".into()]).unwrap();
        let data = engine.volumes.mountpoint("data");
        std::fs::rename(&data, root.path().join("retained-data")).unwrap();
        std::fs::create_dir(&data).unwrap();
        assert_ne!(
            first.fingerprint,
            build(&engine, &["web".into()]).unwrap().fingerprint
        );
        let vm = crate::config::VmRecord::new(a.machine.clone(), 1, 512, vec![], vec![], false);
        engine.db.insert_vm(&a.machine, &vm).unwrap();
        let plan = build(&engine, &["web".into()]).unwrap();
        assert!(plan
            .blockers
            .iter()
            .any(|b| b.code == "machine_ownership_mismatch"));
    }
    fn running_vm(engine: &Engine, name: &str, owner: Option<&str>) {
        let mut vm = crate::config::VmRecord::new(name.into(), 1, 128, vec![], vec![], false);
        vm.pid = Some(std::process::id() as i32);
        assert!(vm.is_process_alive());
        if let Some(owner) = owner {
            vm.labels
                .insert(super::super::containers::MACHINE_LABEL.into(), owner.into());
        }
        engine.db.insert_vm(name, &vm).unwrap();
    }

    #[test]
    fn transfer_preflight_finds_unrecorded_live_volume_users_including_readers_and_aliases() {
        let root = tempfile::tempdir().unwrap();
        let engine = super::super::test_engine(root.path());
        let a = record(&engine, 'a', "web", Some("data"));
        running_vm(&engine, &a.machine, Some(&a.id));
        running_vm(&engine, "outside", None);
        let data = engine.volumes.mountpoint("data");
        std::fs::create_dir(data.join("child")).unwrap();
        let alias = root.path().join("alias");
        std::os::unix::fs::symlink(&data, &alias).unwrap();
        for source in [
            alias,
            data.clone(),
            data.join("child"),
            data.parent().unwrap().to_owned(),
        ] {
            for read_only in [false, true] {
                let mut observed = Vec::new();
                let plan = build_with_inventory(&engine, &["web".into()], |name, deadline| {
                    assert!(deadline > Instant::now());
                    observed.push(name.to_owned());
                    Ok(if name == "outside" {
                        vec![LiveShare {
                            name: "hidden".into(),
                            source: source.clone(),
                            read_only,
                        }]
                    } else {
                        vec![]
                    })
                })
                .unwrap();
                assert_eq!(observed.len(), 2);
                assert!(
                    plan.blockers
                        .iter()
                        .any(|b| b.code == "external_live_volume_user"
                            && b.resource == "outside:data")
                );
                assert!(engine
                    .db
                    .get_vm("outside")
                    .unwrap()
                    .unwrap()
                    .mounts
                    .is_empty());
            }
        }
    }

    #[test]
    fn transfer_preflight_binds_selected_live_exports_without_hashing_unrelated_exports() {
        let root = tempfile::tempdir().unwrap();
        let engine = super::super::test_engine(root.path());
        let a = record(&engine, 'a', "web", Some("data"));
        running_vm(&engine, &a.machine, Some(&a.id));
        running_vm(&engine, "outside", None);
        let unrelated = root.path().join("unrelated");
        std::fs::create_dir(&unrelated).unwrap();
        let build_plan = |selected_read_only, outside_read_only| {
            build_with_inventory(&engine, &["web".into()], |name, _| {
                let selected = name == a.machine;
                Ok(vec![LiveShare {
                    name: "dynamic".into(),
                    source: if selected {
                        engine.volumes.mountpoint("data")
                    } else {
                        unrelated.clone()
                    },
                    read_only: if selected {
                        selected_read_only
                    } else {
                        outside_read_only
                    },
                }])
            })
            .unwrap()
        };
        let first = build_plan(false, false);
        assert!(first
            .blockers
            .iter()
            .any(|b| b.code == "live_share_relocation_required"));
        assert!(!first
            .blockers
            .iter()
            .any(|b| b.code == "external_live_volume_user"));
        assert_ne!(first.fingerprint, build_plan(true, false).fingerprint);
        assert_eq!(first.fingerprint, build_plan(false, true).fingerprint);
        assert!(!serde_json::to_string(&first)
            .unwrap()
            .contains(&unrelated.to_string_lossy().to_string()));
    }

    #[test]
    fn transfer_preflight_refuses_unreadable_live_inventory_and_unverified_saved_exports() {
        let root = tempfile::tempdir().unwrap();
        let engine = super::super::test_engine(root.path());
        let a = record(&engine, 'a', "web", Some("data"));
        running_vm(&engine, &a.machine, Some(&a.id));
        running_vm(&engine, "outside", None);
        let plan = build_with_inventory(&engine, &["web".into()], |_, _| {
            Err(crate::Error::agent("inventory", "runtime unavailable"))
        })
        .unwrap();
        assert_eq!(
            plan.blockers
                .iter()
                .filter(|b| b.code == "live_machine_shares_unverified")
                .count(),
            2
        );
        for name in [&a.machine, &"outside".to_string()] {
            engine
                .db
                .update_vm(name, |vm| {
                    vm.pid = None;
                    vm.paused_checkpoint = Some(root.path().join("saved.checkpoint"));
                })
                .unwrap();
        }
        let plan = build_with_inventory(&engine, &["web".into()], |_, _| {
            panic!("must not start a paused machine to inspect it")
        })
        .unwrap();
        assert_eq!(
            plan.blockers
                .iter()
                .filter(|b| b.code == "saved_machine_shares_unverified")
                .count(),
            2
        );
    }
}
