//! Warm bases: containers that branch from a booted machine instead of booting.
//!
//! When an image starts while [`RUNNING_BEFORE_BASE`] containers of it (at
//! the same size) already run, the engine boots one more machine from it
//! with nothing running in it: the image's base. Later containers of that
//! image branch from the base, paused, instead of booting: a branch starts
//! from the base's memory and disks and shares them until it writes, so
//! each such container costs only what it changes.
//!
//! A base costs about what one booted container costs, and a branch starts
//! no faster than a boot, so a base pays off only for many containers of one
//! image at once (a test suite's parallel databases, `compose up --scale`).
//! An image started one container at a time never gets one.
//!
//! A container branches only on its first start, and only when everything
//! that differs between containers can be set after the branch: its
//! addresses and networks (the guest's address is moved with
//! `SetPrimaryAddress`), its ports and egress policy (the host side of the
//! network starts from the container's own record), and its command,
//! environment and user (`ContainerStart`). Mounts are devices fixed at
//! boot, so a container that mounts host directories or sockets boots as
//! usual. Any failure to branch falls back to booting.
//!
//! Branching is on where a branch's disks are as fast as a booted
//! machine's: on macOS they are file clones. On Linux a branch's disks are
//! copy-on-write overlay images, and writing to them is several times
//! slower than to the raw disks a booted machine gets, which a database in
//! a container feels; containers boot there unless `SMOLVM_ENGINE_BRANCH=1`
//! is set (and `SMOLVM_ENGINE_BRANCH=0` turns branching off on macOS).
//!
//! The disks of a branched container build on its base, so a base is kept
//! while containers branched from it exist. A base unused for [`IDLE`] is
//! retired: it stops once no container branched from it runs, and is
//! deleted with the last one.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::Engine;
use crate::config::VmRecord;

/// Label on base machines; its value is the base's key.
pub(crate) const BASE_LABEL: &str = "smolvm.engine/base";

/// How long a base stays ready without a container branching from it.
const IDLE: Duration = Duration::from_secs(120);

/// Containers of one image (and size) running when another starts before
/// the engine builds the image's base.
const RUNNING_BEFORE_BASE: usize = 2;

/// The bases the engine keeps, by key.
#[derive(Default)]
pub(crate) struct Bases {
    inner: parking_lot::Mutex<HashMap<String, Base>>,
    /// The running bases' machines, by name. A handle owns its machine:
    /// dropping it stops the machine.
    handles: parking_lot::Mutex<HashMap<String, crate::embedded::handle::VmHandle>>,
}

struct Base {
    status: Status,
    last_used: Instant,
}

enum Status {
    /// Not built: containers of this key boot.
    Cold,
    /// Booting in the background under this machine name.
    Building(String),
    /// Running (or paused after the first branch) under this machine name.
    Ready(String),
    /// Building or branching failed; this key boots from now on.
    Failed,
}

/// Whether containers branch from warm bases on this host.
fn enabled() -> bool {
    match std::env::var("SMOLVM_ENGINE_BRANCH").as_deref() {
        Ok("1") => true,
        Ok("0") => false,
        _ => cfg!(target_os = "macos"),
    }
}

/// The base a container's machine could branch from, or `None` when the
/// machine needs something a branch cannot change after boot.
fn key(vm: &VmRecord) -> Option<String> {
    let eligible = vm.mounts.is_empty()
        && vm.published_sockets.is_empty()
        && vm.disks.is_empty()
        && vm.switch.is_some()
        && vm.network_backend == Some(crate::network::NetworkBackend::VirtioNet)
        && !vm.cuda
        && vm.gpu != Some(true);
    if !eligible {
        return None;
    }
    let image = vm.image.as_deref()?;
    Some(format!(
        "{image} cpus={} mem={} rosetta={}",
        vm.cpus,
        vm.mem,
        vm.rosetta.unwrap_or(false)
    ))
}

/// Take what makes a container itself from its own record onto the record
/// of a machine branched from a base.
fn adjust(clone: &mut VmRecord, own: &VmRecord) {
    clone.ports = own.ports.clone();
    clone.udp_ports = own.udp_ports.clone();
    clone.allowed_cidrs = own.allowed_cidrs.clone();
    clone.egress_rules = own.egress_rules.clone();
    clone.dns = own.dns;
    clone.dns_options = own.dns_options.clone();
    clone.switch = own.switch.clone();
    clone.labels = own.labels.clone();
    clone.network = own.network;
    clone.network_backend = own.network_backend;
}

impl Bases {
    /// Whether the machine would branch from a ready base, so creating it
    /// need not seed its storage.
    pub(crate) fn ready_for(&self, vm: &VmRecord) -> bool {
        key(vm).is_some_and(|key| {
            matches!(
                self.inner.lock().get(&key).map(|b| &b.status),
                Some(Status::Ready(_))
            )
        })
    }

    /// Note a start of `vm`'s key; returns the base to branch from, if one
    /// is ready, and starts building one once enough containers of the key
    /// run at once.
    fn note_start(&self, engine: &Arc<Engine>, vm: &VmRecord, key: &str) -> Option<String> {
        let ready = {
            let mut inner = self.inner.lock();
            let base = inner.entry(key.to_string()).or_insert(Base {
                status: Status::Cold,
                last_used: Instant::now(),
            });
            match &base.status {
                Status::Ready(name) => {
                    base.last_used = Instant::now();
                    Some(name.clone())
                }
                _ => None,
            }
        };
        if ready.is_some() {
            return ready;
        }
        let running = running_of_key(engine, key);
        let mut inner = self.inner.lock();
        let base = inner.get_mut(key)?;
        if !matches!(base.status, Status::Cold) {
            return None;
        }
        if running >= RUNNING_BEFORE_BASE {
            base.last_used = Instant::now();
            let name = format!("docker-base-{}", &super::util::new_id()[..12]);
            base.status = Status::Building(name.clone());
            let (engine, vm, key) = (engine.clone(), vm.clone(), key.to_string());
            std::thread::spawn(move || build(&engine, &vm, &key, &name));
        }
        None
    }

    fn set(&self, key: &str, status: Status) {
        if let Some(base) = self.inner.lock().get_mut(key) {
            base.status = status;
        }
    }

    /// The bases being built or ready: not to be collected.
    fn current(&self) -> Vec<String> {
        self.inner
            .lock()
            .values()
            .filter_map(|b| match &b.status {
                Status::Building(name) | Status::Ready(name) => Some(name.clone()),
                _ => None,
            })
            .collect()
    }

    /// Retire bases nobody branched from for [`IDLE`].
    fn retire_idle(&self) {
        let mut inner = self.inner.lock();
        for base in inner.values_mut() {
            if matches!(base.status, Status::Ready(_)) && base.last_used.elapsed() > IDLE {
                base.status = Status::Cold;
            }
        }
    }

    /// Retire every base (the engine is going away).
    fn retire_all(&self) {
        self.inner.lock().clear();
    }
}

/// How many running containers' machines have `key`.
fn running_of_key(engine: &Arc<Engine>, key: &str) -> usize {
    let machines: Vec<String> = engine
        .containers
        .read()
        .values()
        .filter(|c| c.is_running())
        .map(|c| c.record().machine)
        .collect();
    machines
        .iter()
        .filter(|m| {
            engine
                .db
                .get_vm(m)
                .ok()
                .flatten()
                .and_then(|vm| self::key(&vm))
                .as_deref()
                == Some(key)
        })
        .count()
}

/// Boot the base for `key` from the image `template` runs, in the background.
fn build(engine: &Arc<Engine>, template: &VmRecord, key: &str, name: &str) {
    let name = name.to_string();
    let built = (|| -> crate::Result<crate::embedded::handle::VmHandle> {
        let image = template
            .image
            .clone()
            .ok_or_else(|| crate::Error::config("warm base", "the container has no image"))?;
        let mut labels = BTreeMap::new();
        labels.insert(BASE_LABEL.to_string(), key.to_string());
        let spec = crate::machine_spec::CreateSpec {
            net: true,
            network_backend: Some(crate::network::NetworkBackend::VirtioNet),
            cpus: Some(template.cpus),
            mem: Some(template.mem),
            rosetta: template.rosetta.unwrap_or(false),
            forkable: true,
            labels,
            ..Default::default()
        };
        crate::embedded::control::create_vm_from_spec(&engine.db, &name, Some(&image), spec)?;
        let started = crate::embedded::control::start_vm(&engine.db, &name)?;
        let mut client =
            crate::agent::AgentClient::connect_with_retry(started.handle.agent_socket())?;
        if client.query(&image)?.is_none() {
            client.pull_with_registry_config(&image)?;
        }
        // A branch resets its identity files in its source's container
        // overlay, so the base gets one. Whether the image has `true` does
        // not matter: the overlay exists before the command runs.
        let mut run = crate::agent::RunConfig::new(&image, vec!["true".into()])
            .with_persistent_overlay(Some(name.clone()));
        run.timeout = Some(Duration::from_secs(60));
        client.run_non_interactive(run)?;
        Ok(started.handle)
    })();
    match built {
        Ok(handle) => {
            tracing::info!(base = %name, %key, "warm base ready");
            engine.bases.handles.lock().insert(name.clone(), handle);
            engine.bases.set(key, Status::Ready(name));
        }
        Err(error) => {
            tracing::warn!(base = %name, %key, %error, "could not build a warm base; containers of this image boot");
            engine.bases.set(key, Status::Failed);
            let _ = crate::embedded::control::stop_vm_with_timeout(
                &engine.db,
                &name,
                Some(Duration::ZERO),
            );
            let _ = crate::embedded::control::delete_vm(&engine.db, &name);
        }
    }
}

/// Boot the never-started machine `machine` by branching it from its
/// image's base, when there is one. `None` means boot it as usual.
pub(crate) fn branch(
    engine: &Arc<Engine>,
    machine: &str,
) -> Option<crate::embedded::handle::VmHandle> {
    if !enabled() {
        return None;
    }
    let own = engine.db.get_vm(machine).ok().flatten()?;
    if own.golden.is_some() {
        return None;
    }
    let key = key(&own)?;
    let base = engine.bases.note_start(engine, &own, &key)?;
    // The created machine's record says what the container needs; the
    // branch takes its place under the same name.
    if let Err(error) = crate::embedded::control::delete_vm(&engine.db, machine) {
        tracing::warn!(%machine, %error, "could not replace the machine with a branch");
        return None;
    }
    match crate::embedded::control::fork_vm_adjusted(&engine.db, &base, machine, |clone| {
        adjust(clone, &own)
    }) {
        Ok(handle) => Some(handle),
        Err(error) => {
            tracing::warn!(%machine, %base, %error, "could not branch from the warm base; booting instead");
            engine.bases.set(&key, Status::Failed);
            if let Err(error) = engine.db.insert_vm(machine, &own) {
                tracing::warn!(%machine, %error, "could not restore the machine record");
            }
            None
        }
    }
}

/// Stop retired bases no running container depends on, and delete the ones
/// no container depends on at all.
pub(crate) fn collect(engine: &Arc<Engine>) {
    let current = engine.bases.current();
    let Ok(vms) = engine.db.list_vms() else {
        return;
    };
    for (name, vm) in vms {
        if !vm.labels.contains_key(BASE_LABEL) || current.contains(&name) {
            continue;
        }
        let dependents = engine.db.dependent_clones(&name).unwrap_or_default();
        let live = crate::agent::fork::stop_blocking_dependent_clones(&engine.db, &name)
            .unwrap_or_else(|_| vec![name.clone()]);
        if live.is_empty() {
            stop_base(engine, &name, &vm);
        }
        let alive = engine
            .db
            .get_vm(&name)
            .ok()
            .flatten()
            .is_some_and(|vm| vm.is_process_alive());
        if dependents.is_empty() && !alive {
            if let Err(error) = crate::embedded::control::delete_vm(&engine.db, &name) {
                tracing::debug!(base = %name, %error, "could not delete a retired base");
            }
        }
    }
}

/// Stop a base. One that has been branched is paused, and its agent cannot
/// answer a shutdown request.
fn stop_base(engine: &Arc<Engine>, name: &str, vm: &VmRecord) {
    let frozen =
        crate::agent::state_probe::resolve_state(name, vm) == crate::config::RecordState::Frozen;
    let handle = engine.bases.handles.lock().remove(name);
    let stopped = match handle {
        Some(mut handle) if frozen => handle.stop_paused(),
        Some(mut handle) => handle.stop_with_timeout(Some(Duration::ZERO)),
        None if !vm.is_process_alive() => Ok(()),
        None if frozen => crate::agent::AgentManager::for_vm(name).and_then(|m| m.stop_paused()),
        None => {
            crate::embedded::control::stop_vm_with_timeout(&engine.db, name, Some(Duration::ZERO))
        }
    };
    match stopped {
        Ok(()) => {
            let _ = crate::embedded::control::mark_stopped(&engine.db, name);
        }
        Err(error) => tracing::warn!(base = %name, %error, "could not stop a retired base"),
    }
}

/// Retire idle bases every minute.
pub(crate) fn spawn_reaper(engine: &Arc<Engine>) {
    let engine = engine.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            engine.bases.retire_idle();
            let e = engine.clone();
            let _ = tokio::task::spawn_blocking(move || collect(&e)).await;
        }
    });
}

/// Retire and collect every base, as the engine exits.
pub(crate) async fn shutdown(engine: &Arc<Engine>) {
    engine.bases.retire_all();
    let e = engine.clone();
    let _ = tokio::task::spawn_blocking(move || collect(&e)).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> VmRecord {
        let mut vm = VmRecord::new("docker-x".into(), 1, 512, vec![], vec![], true);
        vm.image = Some("docker.io/library/alpine@sha256:abc".into());
        vm.network_backend = Some(crate::network::NetworkBackend::VirtioNet);
        vm.switch = Some(crate::data::network::SwitchAttachment {
            dir: "/tmp/sw".into(),
            endpoint: "abc".into(),
        });
        vm
    }

    #[test]
    fn only_machines_without_boot_time_devices_branch() {
        let vm = record();
        assert!(key(&vm).is_some());
        let mut mounted = vm.clone();
        mounted.mounts.push(("/src".into(), "/dst".into(), false));
        assert!(key(&mounted).is_none());
        let mut offline = vm.clone();
        offline.switch = None;
        assert!(key(&offline).is_none());
        let mut bigger = vm.clone();
        bigger.mem = 1024;
        assert_ne!(key(&bigger), key(&vm));
    }

    #[test]
    fn a_branch_takes_the_containers_network_and_ports() {
        let own = {
            let mut vm = record();
            vm.ports = vec![(8080, 80)];
            vm.dns_options = vec!["ndots:2".into()];
            vm
        };
        let mut clone = record();
        clone.switch = None;
        clone.golden = Some("docker-base-1".into());
        adjust(&mut clone, &own);
        assert_eq!(clone.ports, vec![(8080, 80)]);
        assert_eq!(clone.switch, own.switch);
        assert_eq!(clone.dns_options, own.dns_options);
        assert_eq!(clone.golden.as_deref(), Some("docker-base-1"));
    }
}
