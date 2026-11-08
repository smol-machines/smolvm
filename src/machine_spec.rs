//! One description of a new machine, and the one place it is resolved.
//!
//! Every way of creating a machine builds a [`CreateSpec`] from its own input
//! and hands it to [`resolve`] together with where the machine's root
//! filesystem comes from ([`SpecSource`]): `machine create` (no image, an
//! image, a `.smolmachine` pack, a live checkpoint, with or without a
//! Smolfile), the serve API's create and checkpoint restore, and the embedded
//! runtime that the SDKs drive. The result writes the machine record in one
//! place, [`ResolvedSpec::to_record`].
//!
//! Merge rules, applied the same way on every path:
//!
//! - **No image or an image.** Each option takes its explicit value, else the
//!   engine default.
//! - **A pack.** The manifest supplies defaults: CPUs, memory, entrypoint and
//!   command, environment, working directory, user, networking, GPU and CUDA.
//!   An explicit scalar replaces the packed value; an explicit command replaces
//!   the packed entrypoint and command together; explicit environment
//!   variables are merged over the packed ones by name; a flag (`net`, `gpu`,
//!   `cuda`) is on when either side turns it on. A packed secret reference must
//!   be bound by an explicit one of the same name, because a pack is untrusted
//!   and may not choose where on this host a value is read from.
//! - **A live checkpoint.** The guest resumes with the CPUs, memory, disks,
//!   devices, network and workload it was captured with, so the checkpoint
//!   fixes them. An explicit option that asks for anything different is
//!   refused with the option's name, never dropped. Settings enforced on the
//!   host take an explicit value over the captured one: the egress policy
//!   (allow-lists, rules, block-private) on the captured backend, the host
//!   side of the captured guest ports, restart, stop and health settings,
//!   the block I/O engine and disk durability, environment and working
//!   directory for later commands, and labels.
//!
//! [`CreateSpec`] lists every option, and both [`resolve`] and
//! [`ResolvedSpec::to_record`] destructure it without `..`, so a new option
//! does not compile until each path decides what it means.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::config::{PublishedSocketConfig, RecordState, RestartConfig, RestartPolicy, VmRecord};
use crate::credentials::CredentialPolicy;
use crate::data::disk::{AttachedDisk, CacheDisk};
use crate::data::network::PortMapping;
use crate::data::resources::{
    default_microvm_memory_mib, BlockIoEngine, DiskDurability, DEFAULT_MICROVM_CPU_COUNT,
};
use crate::data::storage::HostMount;
use crate::network::NetworkBackend;
use crate::remote_volume::RemoteVolume;
use crate::secrets::SecretRef;
use crate::{Error, Result};
use smolvm_pack::format::{PackManifest, PackMode, PortableCheckpointManifest};
use smolvm_protocol::EgressRule;

/// Everything a caller can ask of a new machine, whatever its root
/// filesystem comes from. An unset option (`None`, empty, `false`) takes the
/// source's value or the engine default; see the module docs for the rules.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CreateSpec {
    // Workload ---------------------------------------------------------------
    /// Workload entrypoint. Set together with or without `cmd`, it replaces
    /// the source's entrypoint and command as a pair.
    pub entrypoint: Option<Vec<String>>,
    /// Workload command (arguments to the entrypoint).
    pub cmd: Option<Vec<String>>,
    /// Workload environment, merged over the source's by name.
    pub env: Vec<(String, String)>,
    /// Working directory of the workload and of commands run in the machine.
    pub workdir: Option<String>,
    /// User the workload runs as (name or `uid[:gid]`).
    pub user: Option<String>,
    /// Commands run once, on the machine's first start.
    pub init: Vec<String>,
    /// Secret references resolved into the environment at each start. Only
    /// the reference is stored, never the value.
    pub secret_refs: BTreeMap<String, SecretRef>,
    /// Restart policy.
    pub restart_policy: Option<RestartPolicy>,
    /// Maximum automatic restarts (`0` means unlimited).
    pub restart_max_retries: Option<u32>,
    /// Maximum restart backoff in seconds.
    pub restart_max_backoff_secs: Option<u64>,
    /// Health check command run in the machine.
    pub health_cmd: Option<Vec<String>>,
    /// Seconds between health checks.
    pub health_interval_secs: Option<u64>,
    /// Seconds a health check may take.
    pub health_timeout_secs: Option<u64>,
    /// Failed checks before the workload counts as unhealthy.
    pub health_retries: Option<u32>,
    /// Seconds after boot before health checks start.
    pub health_startup_grace_secs: Option<u64>,
    /// Stop the machine once its workload exits.
    pub stop_on_exit: bool,
    /// Signal the workload is sent when the machine stops.
    pub stop_signal: Option<String>,
    /// Seconds the workload gets to exit after its stop signal.
    pub stop_timeout_secs: Option<u64>,
    /// `/dev/shm` size of the workload (`512m`, `25%`).
    pub shm_size: Option<String>,

    // Resources --------------------------------------------------------------
    /// vCPUs.
    pub cpus: Option<u8>,
    /// Memory in MiB.
    pub mem: Option<u32>,
    /// Storage disk size in GiB.
    pub storage_gb: Option<u64>,
    /// Overlay disk size in GiB.
    pub overlay_gb: Option<u64>,
    /// Host engine for writable block disks.
    pub block_io: Option<BlockIoEngine>,
    /// When guest disk writes must reach the host's disk.
    pub disk_durability: Option<DiskDurability>,
    /// Host disks attached beyond storage and overlay.
    pub disks: Vec<AttachedDisk>,
    /// Shared cache disk.
    pub cache_disk: Option<CacheDisk>,

    // Filesystems ------------------------------------------------------------
    /// Host directories mounted into the guest (live or staged).
    pub mounts: Vec<HostMount>,
    /// S3-compatible volumes mounted inside the guest.
    pub remote_volumes: Vec<RemoteVolume>,
    /// Guest paths backed by the machine's storage disk.
    pub disk_volumes: Vec<String>,

    // Network ----------------------------------------------------------------
    /// Outbound networking. Also turned on by any option that needs it.
    pub net: bool,
    /// Network backend.
    pub network_backend: Option<NetworkBackend>,
    /// Guest DNS resolver.
    pub dns: Option<std::net::Ipv4Addr>,
    /// Guest resolv.conf options, in order.
    pub dns_options: Vec<String>,
    /// Named inter-VM network.
    pub network_name: Option<String>,
    /// Canonical guest link subnet.
    pub guest_subnet: Option<String>,
    /// Published ports (TCP and UDP).
    pub ports: Vec<PortMapping>,
    /// Egress CIDR allow-list (`Some([])` denies everything).
    pub allowed_cidrs: Option<Vec<String>>,
    /// Egress hostname allow-list.
    pub allowed_hosts: Option<Vec<String>>,
    /// Block private destinations, with these exceptions.
    pub block_private: Option<Vec<String>>,
    /// Ordered L4 egress rules.
    pub egress_rules: Vec<EgressRule>,
    /// Credential bindings.
    pub credentials: Option<CredentialPolicy>,
    /// Credential values come only from what the caller supplies, never from
    /// this host's environment. Always so for the API and for bindings a
    /// checkpoint brings.
    pub credentials_supplied_only: bool,
    /// Unix-socket bridges between host and guest.
    pub published_sockets: Vec<PublishedSocketConfig>,

    // Devices ----------------------------------------------------------------
    /// Vulkan GPU (virtio-gpu).
    pub gpu: bool,
    /// GPU shared-memory size in MiB.
    pub gpu_vram_mib: Option<u32>,
    /// Rosetta x86_64 translation.
    pub rosetta: bool,
    /// Nested virtualization.
    pub nested_virt: bool,
    /// CUDA over vsock.
    pub cuda: bool,
    /// Expose the guest's Docker socket.
    pub docker_socket: bool,
    /// Forward the host's SSH agent.
    pub ssh_agent: bool,

    // Branching and lifecycle -----------------------------------------------
    /// Start as a branch source on every start.
    pub forkable: bool,
    /// Planned number of runnable CUDA branch children.
    pub cuda_fork_pool_size: Option<u32>,
    /// Logical VRAM limit per CUDA session, in MiB.
    pub cuda_vram_limit_mib: Option<u64>,
    /// Keep a checkpoint's hostname and machine id on restore.
    pub keep_identity: bool,
    /// Removed when its creating process is done with it.
    pub ephemeral: bool,
    /// Outlives the process that starts it.
    pub detached: bool,
    /// Managed by the Kubernetes runtime shim.
    pub runtime_managed: bool,
    /// Caller metadata.
    pub labels: BTreeMap<String, String>,
}

impl CreateSpec {
    /// `top` laid over `self`: a set option in `top` replaces this one, a
    /// list or map in `top` adds to this one (environment variables and keys
    /// by name), and a flag is on when either turns it on. Ordered lists whose
    /// order is their meaning (resolver options, egress rules) are replaced
    /// whole.
    pub fn overlay(self, top: CreateSpec) -> CreateSpec {
        fn list<T>(mut base: Vec<T>, top: Vec<T>) -> Vec<T> {
            base.extend(top);
            base
        }
        fn replace<T>(base: Vec<T>, top: Vec<T>) -> Vec<T> {
            if top.is_empty() {
                base
            } else {
                top
            }
        }
        fn opt_list<T: PartialEq>(base: Option<Vec<T>>, top: Option<Vec<T>>) -> Option<Vec<T>> {
            match (base, top) {
                (Some(mut base), Some(top)) => {
                    for item in top {
                        if !base.contains(&item) {
                            base.push(item);
                        }
                    }
                    Some(base)
                }
                (base, top) => top.or(base),
            }
        }
        fn map<K: Ord, V>(mut base: BTreeMap<K, V>, top: BTreeMap<K, V>) -> BTreeMap<K, V> {
            base.extend(top);
            base
        }
        let CreateSpec {
            entrypoint,
            cmd,
            env,
            workdir,
            user,
            init,
            secret_refs,
            restart_policy,
            restart_max_retries,
            restart_max_backoff_secs,
            health_cmd,
            health_interval_secs,
            health_timeout_secs,
            health_retries,
            health_startup_grace_secs,
            stop_on_exit,
            stop_signal,
            stop_timeout_secs,
            shm_size,
            cpus,
            mem,
            storage_gb,
            overlay_gb,
            block_io,
            disk_durability,
            disks,
            cache_disk,
            mounts,
            remote_volumes,
            disk_volumes,
            net,
            network_backend,
            dns,
            dns_options,
            network_name,
            guest_subnet,
            ports,
            allowed_cidrs,
            allowed_hosts,
            block_private,
            egress_rules,
            credentials,
            credentials_supplied_only,
            published_sockets,
            gpu,
            gpu_vram_mib,
            rosetta,
            nested_virt,
            cuda,
            docker_socket,
            ssh_agent,
            forkable,
            cuda_fork_pool_size,
            cuda_vram_limit_mib,
            keep_identity,
            ephemeral,
            detached,
            runtime_managed,
            labels,
        } = top;
        let (entrypoint, cmd) = if entrypoint.is_some() || cmd.is_some() {
            (entrypoint, cmd)
        } else {
            (self.entrypoint, self.cmd)
        };
        CreateSpec {
            entrypoint,
            cmd,
            env: merge_env(self.env, env),
            workdir: workdir.or(self.workdir),
            user: user.or(self.user),
            init: list(self.init, init),
            secret_refs: map(self.secret_refs, secret_refs),
            restart_policy: restart_policy.or(self.restart_policy),
            restart_max_retries: restart_max_retries.or(self.restart_max_retries),
            restart_max_backoff_secs: restart_max_backoff_secs.or(self.restart_max_backoff_secs),
            health_cmd: health_cmd.or(self.health_cmd),
            health_interval_secs: health_interval_secs.or(self.health_interval_secs),
            health_timeout_secs: health_timeout_secs.or(self.health_timeout_secs),
            health_retries: health_retries.or(self.health_retries),
            health_startup_grace_secs: health_startup_grace_secs.or(self.health_startup_grace_secs),
            stop_on_exit: stop_on_exit || self.stop_on_exit,
            stop_signal: stop_signal.or(self.stop_signal),
            stop_timeout_secs: stop_timeout_secs.or(self.stop_timeout_secs),
            shm_size: shm_size.or(self.shm_size),
            cpus: cpus.or(self.cpus),
            mem: mem.or(self.mem),
            storage_gb: storage_gb.or(self.storage_gb),
            overlay_gb: overlay_gb.or(self.overlay_gb),
            block_io: block_io.or(self.block_io),
            disk_durability: disk_durability.or(self.disk_durability),
            disks: list(self.disks, disks),
            cache_disk: cache_disk.or(self.cache_disk),
            mounts: list(self.mounts, mounts),
            remote_volumes: list(self.remote_volumes, remote_volumes),
            disk_volumes: list(self.disk_volumes, disk_volumes),
            net: net || self.net,
            network_backend: network_backend.or(self.network_backend),
            dns: dns.or(self.dns),
            dns_options: replace(self.dns_options, dns_options),
            network_name: network_name.or(self.network_name),
            guest_subnet: guest_subnet.or(self.guest_subnet),
            ports: list(self.ports, ports),
            allowed_cidrs: opt_list(self.allowed_cidrs, allowed_cidrs),
            allowed_hosts: opt_list(self.allowed_hosts, allowed_hosts),
            block_private: opt_list(self.block_private, block_private),
            egress_rules: replace(self.egress_rules, egress_rules),
            credentials: match (self.credentials, credentials) {
                (Some(mut base), Some(top)) => {
                    base.credentials.extend(top.credentials);
                    Some(base)
                }
                (base, top) => top.or(base),
            },
            credentials_supplied_only: credentials_supplied_only || self.credentials_supplied_only,
            published_sockets: list(self.published_sockets, published_sockets),
            gpu: gpu || self.gpu,
            gpu_vram_mib: gpu_vram_mib.or(self.gpu_vram_mib),
            rosetta: rosetta || self.rosetta,
            nested_virt: nested_virt || self.nested_virt,
            cuda: cuda || self.cuda,
            docker_socket: docker_socket || self.docker_socket,
            ssh_agent: ssh_agent || self.ssh_agent,
            forkable: forkable || self.forkable,
            cuda_fork_pool_size: cuda_fork_pool_size.or(self.cuda_fork_pool_size),
            cuda_vram_limit_mib: cuda_vram_limit_mib.or(self.cuda_vram_limit_mib),
            keep_identity: keep_identity || self.keep_identity,
            ephemeral: ephemeral || self.ephemeral,
            detached: detached || self.detached,
            runtime_managed: runtime_managed || self.runtime_managed,
            labels: map(self.labels, labels),
        }
    }
}

/// Who is creating the machine, which decides what its secret references
/// and credential bindings may read on this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Caller {
    /// The host user at the CLI: secret references of every kind, credential
    /// values from this host's environment.
    Cli,
    /// A process embedding the engine (the SDKs): secret references of every
    /// kind, credential values supplied by the embedder.
    Embedded,
    /// A remote API client: no secret references, credential values supplied
    /// over the API.
    Api,
}

impl Caller {
    fn secret_scope(self) -> crate::secrets::ResolutionScope {
        match self {
            Caller::Cli | Caller::Embedded => crate::secrets::ResolutionScope::TrustedLocal,
            Caller::Api => crate::secrets::ResolutionScope::Untrusted,
        }
    }
}

/// Where a new machine's root filesystem comes from.
#[derive(Debug, Clone, Copy)]
pub enum SpecSource<'a> {
    /// No image: the machine boots the agent rootfs.
    Bare,
    /// An OCI image reference (registry or resolved local reference).
    Image(&'a str),
    /// A `.smolmachine` pack.
    Pack(&'a PackManifest),
    /// A live checkpoint: a `.smolmachine` whose manifest carries one.
    Checkpoint(&'a PackManifest, &'a PortableCheckpointManifest),
}

impl<'a> SpecSource<'a> {
    /// The source a `.smolmachine` manifest describes.
    pub fn from_manifest(manifest: &'a PackManifest) -> Self {
        match manifest.checkpoint.as_ref() {
            Some(checkpoint) => SpecSource::Checkpoint(manifest, checkpoint),
            None => SpecSource::Pack(manifest),
        }
    }

    /// The source an optional image reference describes.
    pub fn from_image(image: Option<&'a str>) -> Self {
        image.map_or(SpecSource::Bare, SpecSource::Image)
    }
}

/// What a restored checkpoint brings with it beyond options: state the
/// captured guest already holds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RestoredState {
    /// Placeholders the captured workload holds for its credential bindings.
    pub credential_placeholders: BTreeMap<String, String>,
    /// Overlay identifier of the captured container.
    pub overlay_owner: Option<String>,
    /// Lineage id the restored machine continues.
    pub checkpoint_head: Option<String>,
    /// The captured machine routed egress through a host mediator.
    pub mediated_egress_required: bool,
    /// The bindings came with the artifact, so their values must be supplied
    /// by the caller, never read from this host's environment.
    pub credentials_from_artifact: bool,
}

/// A [`CreateSpec`] with every rule applied: the machine's settings, ready to
/// be recorded. Only [`resolve`] makes one.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ResolvedSpec {
    /// Who asked for it.
    pub caller: Caller,
    /// OCI image the workload runs from; `None` for a bare or VM-mode machine.
    pub image: Option<String>,
    /// Workload entrypoint.
    pub entrypoint: Vec<String>,
    /// Workload command.
    pub cmd: Vec<String>,
    /// Workload environment.
    pub env: Vec<(String, String)>,
    /// Working directory.
    pub workdir: Option<String>,
    /// Workload user.
    pub user: Option<String>,
    /// First-start commands.
    pub init: Vec<String>,
    /// Secret references.
    pub secret_refs: BTreeMap<String, SecretRef>,
    /// Restart settings.
    pub restart: RestartConfig,
    /// Health check command.
    pub health_cmd: Option<Vec<String>>,
    /// Health check interval.
    pub health_interval_secs: Option<u64>,
    /// Health check timeout.
    pub health_timeout_secs: Option<u64>,
    /// Health check retries.
    pub health_retries: Option<u32>,
    /// Health check grace period.
    pub health_startup_grace_secs: Option<u64>,
    /// Stop once the workload exits.
    pub stop_on_exit: bool,
    /// Stop signal.
    pub stop_signal: Option<String>,
    /// Stop timeout.
    pub stop_timeout_secs: Option<u64>,
    /// `/dev/shm` size.
    pub shm_size: Option<String>,
    /// vCPUs.
    pub cpus: u8,
    /// Memory in MiB.
    pub mem: u32,
    /// Storage disk size in GiB.
    pub storage_gb: Option<u64>,
    /// Overlay disk size in GiB.
    pub overlay_gb: Option<u64>,
    /// Block I/O engine.
    pub block_io: BlockIoEngine,
    /// Disk durability.
    pub disk_durability: DiskDurability,
    /// Attached host disks.
    pub disks: Vec<AttachedDisk>,
    /// Cache disk.
    pub cache_disk: Option<CacheDisk>,
    /// Host mounts.
    pub mounts: Vec<HostMount>,
    /// Remote volumes.
    pub remote_volumes: Vec<RemoteVolume>,
    /// Storage-disk volumes.
    pub disk_volumes: Vec<String>,
    /// Outbound networking.
    pub net: bool,
    /// Network backend.
    pub network_backend: Option<NetworkBackend>,
    /// DNS resolver.
    pub dns: Option<std::net::Ipv4Addr>,
    /// resolv.conf options.
    pub dns_options: Vec<String>,
    /// Named network.
    pub network_name: Option<String>,
    /// Guest subnet.
    pub guest_subnet: Option<String>,
    /// Published ports.
    pub ports: Vec<PortMapping>,
    /// CIDR allow-list.
    pub allowed_cidrs: Option<Vec<String>>,
    /// Hostname allow-list.
    pub allowed_hosts: Option<Vec<String>>,
    /// Private-range block and exceptions.
    pub block_private: Option<Vec<String>>,
    /// Egress rules.
    pub egress_rules: Vec<EgressRule>,
    /// Credential bindings.
    pub credentials: Option<CredentialPolicy>,
    /// Credential values come only from the caller.
    pub credentials_supplied_only: bool,
    /// Socket bridges.
    pub published_sockets: Vec<PublishedSocketConfig>,
    /// Vulkan GPU.
    pub gpu: bool,
    /// GPU VRAM.
    pub gpu_vram_mib: Option<u32>,
    /// Rosetta.
    pub rosetta: bool,
    /// Nested virtualization.
    pub nested_virt: bool,
    /// CUDA.
    pub cuda: bool,
    /// Docker socket.
    pub docker_socket: bool,
    /// SSH agent.
    pub ssh_agent: bool,
    /// Branch source on every start.
    pub forkable: bool,
    /// CUDA branch pool size.
    pub cuda_fork_pool_size: Option<u32>,
    /// CUDA VRAM limit.
    pub cuda_vram_limit_mib: Option<u64>,
    /// Keep a checkpoint's identity.
    pub keep_identity: bool,
    /// Ephemeral.
    pub ephemeral: bool,
    /// Detached.
    pub detached: bool,
    /// Runtime managed.
    pub runtime_managed: bool,
    /// Labels.
    pub labels: BTreeMap<String, String>,
    /// State a restored checkpoint already holds.
    pub restored: Option<RestoredState>,
}

/// Refuse `field` on a live checkpoint restore.
fn fixed(field: &str, why: &str) -> Error {
    Error::config(
        "create from a checkpoint",
        format!("{field} cannot be set when restoring a live checkpoint: {why}"),
    )
}

const TOPOLOGY: &str = "the guest resumes with the devices and resources it was captured with";
const NETWORK: &str = "the guest resumes with the network it was captured with";
const WORKLOAD: &str = "the captured workload is already running";

/// An explicit value that must equal what the checkpoint captured.
fn same<T: PartialEq + std::fmt::Debug>(
    field: &str,
    why: &str,
    asked: Option<T>,
    captured: T,
) -> Result<T> {
    match asked {
        Some(value) if value != captured => Err(fixed(
            field,
            &format!("{why} ({captured:?}, asked for {value:?})"),
        )),
        _ => Ok(captured),
    }
}

/// An explicit list that must be empty or equal what the checkpoint captured.
fn same_list<T: PartialEq + std::fmt::Debug>(
    field: &str,
    why: &str,
    asked: Vec<T>,
    captured: Vec<T>,
) -> Result<Vec<T>> {
    same(field, why, (!asked.is_empty()).then_some(asked), captured)
}

/// A device flag a checkpoint fixes: asking for it on a machine captured
/// without it is refused.
fn same_flag(field: &str, asked: bool, captured: bool) -> Result<bool> {
    if asked && !captured {
        return Err(fixed(field, TOPOLOGY));
    }
    Ok(captured)
}

/// Merge `explicit` over `base` by variable name: an explicit variable
/// replaces a source one of the same name.
fn merge_env(
    base: Vec<(String, String)>,
    explicit: Vec<(String, String)>,
) -> Vec<(String, String)> {
    let mut merged = base;
    for (name, value) in explicit {
        merged.retain(|(existing, _)| existing != &name);
        merged.push((name, value));
    }
    merged
}

/// What a `.smolmachine` manifest says about the options it defaults.
struct PackDefaults {
    image: Option<String>,
    entrypoint: Vec<String>,
    cmd: Vec<String>,
    env: Vec<(String, String)>,
    workdir: Option<String>,
    user: Option<String>,
    secret_refs: BTreeMap<String, SecretRef>,
    cpus: u8,
    mem: u32,
    net: bool,
    gpu: bool,
    cuda: bool,
}

impl PackDefaults {
    fn of(manifest: &PackManifest) -> Self {
        Self {
            // A VM-mode pack carries disks, not an image: its synthetic
            // `vm://` label is not pullable, and an image would route exec
            // through a container that does not exist.
            image: (manifest.mode != PackMode::Vm).then(|| manifest.image.clone()),
            entrypoint: manifest.entrypoint.clone(),
            cmd: manifest.cmd.clone(),
            env: crate::util::parse_env_list(&manifest.env),
            workdir: manifest.workdir.clone(),
            user: manifest.user.clone(),
            secret_refs: manifest.secret_refs.clone(),
            cpus: manifest.cpus,
            mem: manifest.mem,
            net: manifest.network,
            gpu: manifest.gpu,
            cuda: manifest.cuda,
        }
    }
}

/// Bind a source's secret references: an explicit reference of the same name
/// wins, and an unbound packed one is refused, since an untrusted artifact
/// may not choose what on this host a value is read from.
fn bind_secret_refs(
    packed: BTreeMap<String, SecretRef>,
    mut explicit: BTreeMap<String, SecretRef>,
) -> Result<BTreeMap<String, SecretRef>> {
    for (name, reference) in packed {
        if explicit.contains_key(&name) {
            continue;
        }
        crate::secrets::validate_ref(&reference, crate::secrets::ResolutionScope::Untrusted)
            .map_err(|error| {
                Error::config(
                    "create from a .smolmachine",
                    format!(
                        "secret '{name}': {error}; the artifact names it but may not say where its \
                         value comes from, so bind it with a secret of the same name"
                    ),
                )
            })?;
        explicit.insert(name, reference);
    }
    Ok(explicit)
}

/// Resolve `spec` for a machine made from `source` by `caller`.
///
/// This is pure: it reads nothing but its arguments (a checkpoint's host
/// mounts are checked to exist), so every refusal happens before any disk
/// work. See the module docs for the rules.
pub fn resolve(source: SpecSource<'_>, spec: CreateSpec, caller: Caller) -> Result<ResolvedSpec> {
    // Destructured without `..`: a new option fails to compile here until it
    // has a rule for every source.
    let CreateSpec {
        entrypoint,
        cmd,
        env,
        workdir,
        user,
        init,
        secret_refs,
        restart_policy,
        restart_max_retries,
        restart_max_backoff_secs,
        health_cmd,
        health_interval_secs,
        health_timeout_secs,
        health_retries,
        health_startup_grace_secs,
        stop_on_exit,
        stop_signal,
        stop_timeout_secs,
        shm_size,
        cpus,
        mem,
        storage_gb,
        overlay_gb,
        block_io,
        disk_durability,
        disks,
        cache_disk,
        mounts,
        remote_volumes,
        disk_volumes,
        net,
        network_backend,
        dns,
        dns_options,
        network_name,
        guest_subnet,
        ports,
        allowed_cidrs,
        allowed_hosts,
        block_private,
        egress_rules,
        credentials,
        credentials_supplied_only,
        published_sockets,
        gpu,
        gpu_vram_mib,
        rosetta,
        nested_virt,
        cuda,
        docker_socket,
        ssh_agent,
        forkable,
        cuda_fork_pool_size,
        cuda_vram_limit_mib,
        keep_identity,
        ephemeral,
        detached,
        runtime_managed,
        labels,
    } = spec;

    // Input checks that hold for every source.
    for (name, reference) in &secret_refs {
        crate::secrets::validate_ref(reference, caller.secret_scope()).map_err(|error| {
            Error::config("create machine", format!("secret '{name}': {error}"))
        })?;
    }
    crate::workload::validate_stop_settings(stop_signal.as_deref(), stop_timeout_secs)
        .map_err(|error| Error::config("create machine", error))?;
    for option in &dns_options {
        smolvm_protocol::resolv::validate_option(option)
            .map_err(|error| Error::config("create machine", error))?;
    }
    let guest_subnet = guest_subnet
        .map(|subnet| {
            subnet
                .parse::<smolvm_network::GuestSubnet>()
                .map(|subnet| subnet.to_string())
                .map_err(|error| Error::config("create machine", error))
        })
        .transpose()?;
    let allowed_cidrs = allowed_cidrs
        .map(|cidrs| {
            cidrs
                .iter()
                .map(|cidr| crate::smolfile::parse_cidr(cidr))
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|error| Error::config("create machine", error))
        })
        .transpose()?;
    let block_private = block_private
        .map(|cidrs| {
            cidrs
                .iter()
                .map(|cidr| crate::smolfile::parse_cidr(cidr))
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|error| Error::config("create machine", error))
        })
        .transpose()?;
    smolvm_network::EgressPolicy::unrestricted()
        .with_rules(&egress_rules)
        .map_err(|error| Error::config("create machine", error))?;
    for port in &ports {
        if port.host == 0 || port.guest == 0 {
            return Err(Error::config(
                "create machine",
                "port 0 is not valid for VM port forwarding",
            ));
        }
    }
    PortMapping::check_duplicates(&ports)
        .map_err(|error| Error::config("create machine", error))?;
    HostMount::ensure_unique_targets(&mounts)?;
    for volume in &remote_volumes {
        if mounts
            .iter()
            .any(|mount| mount.target.as_os_str() == volume.target.as_str())
            || remote_volumes
                .iter()
                .filter(|other| other.target == volume.target)
                .count()
                > 1
        {
            return Err(Error::config(
                "create machine",
                format!(
                    "duplicate mount target: {} is specified more than once",
                    volume.target
                ),
            ));
        }
    }
    let mount_targets: Vec<String> = mounts
        .iter()
        .map(|mount| mount.target.to_string_lossy().into_owned())
        .collect();
    crate::data::storage::ensure_disk_volumes_distinct(
        &disk_volumes,
        mount_targets
            .iter()
            .map(String::as_str)
            .chain(remote_volumes.iter().map(|volume| volume.target.as_str())),
    )?;
    if cuda_fork_pool_size == Some(0) {
        return Err(Error::config(
            "create machine",
            "fork pool size must be greater than zero",
        ));
    }
    if cuda_vram_limit_mib == Some(0) {
        return Err(Error::config(
            "create machine",
            "CUDA VRAM limit must be greater than zero",
        ));
    }
    let gpu_vram_mib = crate::data::resources::validate_gpu_vram_mib(gpu_vram_mib)
        .map_err(|error| Error::config("create machine", format!("gpu_vram: {error}")))?;
    let has_credentials = credentials
        .as_ref()
        .is_some_and(|policy| !policy.is_empty());
    let credentials = credentials.filter(|policy| !policy.is_empty());
    let explicit_command = entrypoint.is_some() || cmd.is_some();
    // Any option that only makes sense with a network turns it on.
    let implied_net = has_credentials
        || block_private.is_some()
        || dns.is_some()
        || network_name.is_some()
        || guest_subnet.is_some()
        || !egress_rules.is_empty()
        || allowed_cidrs
            .as_ref()
            .is_some_and(|cidrs| !cidrs.is_empty())
        || allowed_hosts
            .as_ref()
            .is_some_and(|hosts| !hosts.is_empty());

    let restart_from =
        |policy: Option<RestartPolicy>, retries: Option<u32>, backoff: Option<u64>| RestartConfig {
            policy: policy.unwrap_or(RestartPolicy::Never),
            max_retries: retries.unwrap_or(0),
            max_backoff_secs: backoff.unwrap_or(0),
            ..Default::default()
        };

    let resolved = match source {
        SpecSource::Bare | SpecSource::Image(_) => {
            if keep_identity {
                return Err(Error::config(
                    "create machine",
                    "keeping a checkpoint's identity needs a checkpoint to restore",
                ));
            }
            ResolvedSpec {
                caller,
                image: match source {
                    SpecSource::Image(image) => Some(image.to_string()),
                    _ => None,
                },
                entrypoint: entrypoint.unwrap_or_default(),
                cmd: cmd.unwrap_or_default(),
                env,
                workdir,
                user,
                init,
                secret_refs,
                restart: restart_from(
                    restart_policy,
                    restart_max_retries,
                    restart_max_backoff_secs,
                ),
                health_cmd,
                health_interval_secs,
                health_timeout_secs,
                health_retries,
                health_startup_grace_secs,
                stop_on_exit,
                stop_signal,
                stop_timeout_secs,
                shm_size,
                cpus: cpus.unwrap_or(DEFAULT_MICROVM_CPU_COUNT),
                mem: mem.unwrap_or_else(default_microvm_memory_mib),
                storage_gb,
                overlay_gb,
                block_io: block_io.unwrap_or_default(),
                disk_durability: disk_durability.unwrap_or_default(),
                disks,
                cache_disk,
                mounts,
                remote_volumes,
                disk_volumes,
                net: net || implied_net,
                network_backend,
                dns,
                dns_options,
                network_name,
                guest_subnet,
                ports,
                allowed_cidrs,
                allowed_hosts,
                block_private,
                egress_rules,
                credentials,
                credentials_supplied_only,
                published_sockets,
                gpu,
                gpu_vram_mib,
                rosetta,
                nested_virt,
                cuda,
                docker_socket,
                ssh_agent,
                forkable: forkable || cuda_fork_pool_size.is_some(),
                cuda_fork_pool_size,
                cuda_vram_limit_mib,
                keep_identity,
                ephemeral,
                detached,
                runtime_managed,
                labels,
                restored: None,
            }
        }
        SpecSource::Pack(manifest) => {
            if keep_identity {
                return Err(Error::config(
                    "create machine",
                    "keeping a checkpoint's identity needs a checkpoint to restore",
                ));
            }
            let pack = PackDefaults::of(manifest);
            let (entrypoint, cmd) = if explicit_command {
                (entrypoint.unwrap_or_default(), cmd.unwrap_or_default())
            } else {
                (pack.entrypoint, pack.cmd)
            };
            ResolvedSpec {
                caller,
                image: pack.image,
                entrypoint,
                cmd,
                env: merge_env(pack.env, env),
                workdir: workdir.or(pack.workdir),
                user: user.or(pack.user),
                init,
                secret_refs: bind_secret_refs(pack.secret_refs, secret_refs)?,
                restart: restart_from(
                    restart_policy,
                    restart_max_retries,
                    restart_max_backoff_secs,
                ),
                health_cmd,
                health_interval_secs,
                health_timeout_secs,
                health_retries,
                health_startup_grace_secs,
                stop_on_exit,
                stop_signal,
                stop_timeout_secs,
                shm_size,
                cpus: cpus.unwrap_or(pack.cpus),
                mem: mem.unwrap_or(pack.mem),
                storage_gb,
                overlay_gb,
                block_io: block_io.unwrap_or_default(),
                disk_durability: disk_durability.unwrap_or_default(),
                disks,
                cache_disk,
                mounts,
                remote_volumes,
                disk_volumes,
                net: net || implied_net || pack.net,
                network_backend,
                dns,
                dns_options,
                network_name,
                guest_subnet,
                ports,
                allowed_cidrs,
                allowed_hosts,
                block_private,
                egress_rules,
                credentials,
                credentials_supplied_only,
                published_sockets,
                gpu: gpu || pack.gpu,
                gpu_vram_mib,
                rosetta,
                nested_virt,
                cuda: cuda || pack.cuda,
                docker_socket,
                ssh_agent,
                forkable: forkable || cuda_fork_pool_size.is_some(),
                cuda_fork_pool_size,
                cuda_vram_limit_mib,
                keep_identity,
                ephemeral,
                detached,
                runtime_managed,
                labels,
                restored: None,
            }
        }
        SpecSource::Checkpoint(manifest, checkpoint) => {
            crate::portable_checkpoint::validate_compatibility(checkpoint)?;
            let pack = PackDefaults::of(manifest);
            let captured_net = checkpoint.network.clone().unwrap_or_default();
            let workload = checkpoint.workload.as_ref();

            // The workload: already running, so its command, user and init
            // are the checkpoint's.
            if explicit_command {
                return Err(fixed("the workload command", WORKLOAD));
            }
            if !init.is_empty() {
                return Err(fixed(
                    "init commands",
                    "the captured guest already ran its first start",
                ));
            }
            let user = same(
                "the workload user",
                WORKLOAD,
                user.map(Some),
                workload.and_then(|workload| workload.user.clone()),
            )?;

            // Resources and devices.
            let cpus = same("cpus", TOPOLOGY, cpus, checkpoint.cpus)?;
            let mem = same("memory", TOPOLOGY, mem, checkpoint.memory_mib)?;
            let storage_gb = same(
                "the storage disk size",
                TOPOLOGY,
                storage_gb.map(Some),
                checkpoint.storage_gib,
            )?;
            let overlay_gb = same(
                "the overlay disk size",
                TOPOLOGY,
                overlay_gb.map(Some),
                checkpoint.overlay_gib,
            )?;
            if !disks.is_empty() {
                return Err(fixed("attached disks", TOPOLOGY));
            }
            if !mounts.is_empty() {
                return Err(fixed("volume mounts", TOPOLOGY));
            }
            if !remote_volumes.is_empty() {
                return Err(fixed("remote volumes", TOPOLOGY));
            }
            if !disk_volumes.is_empty() {
                return Err(fixed("disk volumes", TOPOLOGY));
            }
            if !published_sockets.is_empty() {
                return Err(fixed("published sockets", TOPOLOGY));
            }
            let gpu = same_flag("gpu", gpu, false)?;
            if gpu_vram_mib.is_some() {
                return Err(fixed("GPU VRAM", TOPOLOGY));
            }
            let rosetta = same_flag("rosetta", rosetta, false)?;
            let nested_virt =
                same_flag("nested virtualization", nested_virt, checkpoint.nested_virt)?;
            let cuda = same_flag("cuda", cuda, false)?;
            if cuda_fork_pool_size.is_some() || cuda_vram_limit_mib.is_some() {
                return Err(fixed("a CUDA branch pool", TOPOLOGY));
            }
            let docker_socket = same_flag("the Docker socket", docker_socket, false)?;
            let ssh_agent = same_flag("SSH agent forwarding", ssh_agent, false)?;

            // Network. An egress policy asks for networking too.
            let replaces_policy = allowed_cidrs.is_some()
                || allowed_hosts.is_some()
                || block_private.is_some()
                || !egress_rules.is_empty();
            let net = same_flag("networking", net || replaces_policy, captured_net.enabled)?;
            let network_backend = same(
                "the network backend",
                NETWORK,
                network_backend.map(Some),
                crate::portable_checkpoint::restored_network_backend(checkpoint)?,
            )?;
            let captured_dns = captured_net
                .dns
                .as_deref()
                .map(str::parse::<std::net::Ipv4Addr>)
                .transpose()
                .map_err(|error| Error::config("restore checkpoint DNS", error.to_string()))?;
            let dns = same("the DNS resolver", NETWORK, dns.map(Some), captured_dns)?;
            let dns_options = same_list(
                "DNS options",
                NETWORK,
                dns_options,
                crate::portable_checkpoint::restored_dns_options(checkpoint)?,
            )?;
            let network_name = same(
                "the named network",
                NETWORK,
                network_name.map(Some),
                captured_net.network_name.clone(),
            )?;
            let guest_subnet = same(
                "the guest subnet",
                NETWORK,
                guest_subnet.map(Some),
                crate::portable_checkpoint::restored_guest_subnet(checkpoint)?,
            )?;
            // The egress policy is enforced on the host, so a restore may
            // replace it, as `machine update` may on a restored machine: the
            // backend stays the one the guest's network device was captured
            // with, and TSI cannot enforce a policy at all.
            if replaces_policy && network_backend == Some(NetworkBackend::Tsi) {
                return Err(fixed(
                    "an egress policy",
                    "the checkpoint was captured on the TSI backend, which cannot enforce one",
                ));
            }
            let allowed_cidrs = allowed_cidrs.or_else(|| captured_net.allowed_cidrs.clone());
            let allowed_hosts = allowed_hosts.or_else(|| captured_net.dns_filter_hosts.clone());
            let block_private = block_private.or_else(|| captured_net.block_private.clone());
            let egress_rules = if egress_rules.is_empty() {
                captured_net.egress_rules.clone()
            } else {
                egress_rules
            };
            smolvm_network::EgressPolicy::unrestricted()
                .with_rules(&egress_rules)
                .map_err(|reason| Error::config("restore checkpoint egress rules", reason))?;
            let _ = credentials_supplied_only;
            if credentials.is_some() {
                return Err(fixed(
                    "credential bindings",
                    "the captured workload holds the placeholders of the bindings it was \
                     captured with, and new bindings would mint ones it never received",
                ));
            }
            let credentials = captured_net.credential_policy.clone();
            if let Some(policy) = &credentials {
                // The artifact is untrusted: hold its policy to create's rules.
                policy.validate(allowed_hosts.as_deref()).map_err(|error| {
                    Error::config("restore checkpoint credentials", error.to_string())
                })?;
            }
            // The guest's ports are captured; a restore may move their host
            // side, never add, drop or change a guest port.
            let captured_ports: Vec<PortMapping> = captured_net
                .ports
                .iter()
                .map(|port| PortMapping::new(port.host, port.guest))
                .chain(captured_net.udp_ports.iter().map(|port| PortMapping {
                    host: port.host,
                    guest: port.guest,
                    protocol: crate::data::network::PortProtocol::Udp,
                }))
                .collect();
            let ports = if ports.is_empty() {
                captured_ports
            } else {
                let guests = |list: &[PortMapping]| {
                    let mut guests: Vec<_> = list
                        .iter()
                        .map(|p| {
                            (
                                p.guest,
                                p.protocol == crate::data::network::PortProtocol::Udp,
                            )
                        })
                        .collect();
                    guests.sort_unstable();
                    guests
                };
                if guests(&ports) != guests(&captured_ports) {
                    return Err(fixed(
                        "ports",
                        "a restore may move the host side of the captured guest ports, \
                         but must keep the same guest ports",
                    ));
                }
                ports
            };
            let mounts = crate::portable_checkpoint::restored_host_mounts(checkpoint)?
                .into_iter()
                .map(|(source, target, read_only)| HostMount {
                    source: source.into(),
                    target: target.into(),
                    read_only,
                    staged: false,
                })
                .collect();

            let captured_settings = &checkpoint.settings;
            ResolvedSpec {
                caller,
                image: workload.map(|workload| workload.image.clone()),
                entrypoint: pack.entrypoint,
                cmd: pack.cmd,
                env: merge_env(pack.env, env),
                workdir: workdir.or(pack.workdir),
                user,
                init: Vec::new(),
                secret_refs: bind_secret_refs(pack.secret_refs, secret_refs)?,
                restart: match workload {
                    Some(workload) => RestartConfig {
                        policy: match restart_policy {
                            Some(policy) => policy,
                            None => workload.restart_policy.parse().map_err(|error: String| {
                                Error::config("restore checkpoint restart policy", error)
                            })?,
                        },
                        max_retries: restart_max_retries.unwrap_or(workload.restart_max_retries),
                        max_backoff_secs: restart_max_backoff_secs
                            .unwrap_or(workload.restart_max_backoff_secs),
                        ..Default::default()
                    },
                    None => restart_from(
                        restart_policy,
                        restart_max_retries,
                        restart_max_backoff_secs,
                    ),
                },
                health_cmd: health_cmd.or_else(|| captured_settings.health_cmd.clone()),
                health_interval_secs: health_interval_secs
                    .or(captured_settings.health_interval_secs),
                health_timeout_secs: health_timeout_secs.or(captured_settings.health_timeout_secs),
                health_retries: health_retries.or(captured_settings.health_retries),
                health_startup_grace_secs: health_startup_grace_secs
                    .or(captured_settings.health_startup_grace_secs),
                stop_on_exit: stop_on_exit || captured_settings.stop_on_exit,
                stop_signal: stop_signal.or_else(|| captured_settings.stop_signal.clone()),
                stop_timeout_secs: stop_timeout_secs.or(captured_settings.stop_timeout_secs),
                shm_size: same(
                    "the /dev/shm size",
                    WORKLOAD,
                    shm_size.map(Some),
                    captured_settings.shm_size.clone(),
                )?,
                cpus,
                mem,
                storage_gb,
                overlay_gb,
                block_io: block_io.unwrap_or_default(),
                disk_durability: match disk_durability {
                    Some(durability) => durability,
                    None => crate::portable_checkpoint::restored_disk_durability(checkpoint)?,
                },
                disks: Vec::new(),
                cache_disk,
                mounts,
                remote_volumes: Vec::new(),
                disk_volumes: Vec::new(),
                net,
                network_backend,
                dns,
                dns_options,
                network_name,
                guest_subnet,
                ports,
                allowed_cidrs,
                allowed_hosts,
                block_private,
                egress_rules,
                credentials,
                // Bindings a checkpoint brings never read this host's environment.
                credentials_supplied_only: true,
                published_sockets: Vec::new(),
                gpu,
                gpu_vram_mib: None,
                rosetta,
                nested_virt,
                cuda,
                docker_socket,
                ssh_agent,
                // A restored checkpoint stays eligible to be branched or
                // checkpointed again without a topology-changing restart.
                forkable: true,
                cuda_fork_pool_size: None,
                cuda_vram_limit_mib: None,
                keep_identity,
                ephemeral,
                detached,
                runtime_managed,
                labels,
                restored: Some(RestoredState {
                    credential_placeholders: captured_net.credential_placeholders.clone(),
                    overlay_owner: workload.map(|workload| workload.overlay_owner.clone()),
                    checkpoint_head: checkpoint
                        .lineage
                        .as_ref()
                        .map(|lineage| lineage.id.clone()),
                    mediated_egress_required: captured_net.mediated_egress_required,
                    credentials_from_artifact: captured_net
                        .credential_policy
                        .as_ref()
                        .is_some_and(|policy| !policy.is_empty()),
                }),
            }
        }
    };

    // Checks on the resolved machine.
    if resolved.cuda_fork_pool_size.is_some() && !resolved.cuda {
        return Err(Error::config(
            "create machine",
            "fork pool size requires a CUDA-enabled machine",
        ));
    }
    if resolved.cuda_vram_limit_mib.is_some() && resolved.cuda_fork_pool_size.is_none() {
        return Err(Error::config(
            "create machine",
            "CUDA VRAM limit requires a fork pool size",
        ));
    }
    if let Some(policy) = resolved.credentials.as_ref() {
        if resolved.restored.is_none() {
            policy
                .validate(resolved.allowed_hosts.as_deref())
                .map_err(|error| Error::config("credentials", error.to_string()))?;
            // Values read from this host's environment need a variable to
            // read each one from.
            if caller == Caller::Cli && !resolved.credentials_supplied_by_api() {
                crate::credentials::require_host_sources(policy)?;
            }
        }
    }
    let resources = resolved.vm_resources();
    resources.validate()?;
    crate::network::validate_requested_network_backend(
        &resources,
        resolved.allowed_hosts.as_deref(),
        resolved.ports.len(),
    )?;
    resolved.unrecorded_record_checks()?;
    Ok(resolved)
}

impl ResolvedSpec {
    /// The VM resources this machine launches with.
    pub fn vm_resources(&self) -> crate::data::resources::VmResources {
        crate::data::resources::VmResources {
            cpus: self.cpus,
            memory_mib: self.mem,
            network: self.net,
            network_backend: self.network_backend,
            gpu: self.gpu,
            gpu_vram_mib: self.gpu_vram_mib,
            cuda: self.cuda,
            nested_virt: self.nested_virt,
            rosetta: self.rosetta,
            storage_gib: self.storage_gb,
            overlay_gib: self.overlay_gb,
            block_io: self.block_io,
            disk_durability: self.disk_durability,
            disks: self.disks.clone(),
            cache_disk: self.cache_disk.clone(),
            disk_volumes: self.disk_volumes.clone(),
            block_private: self.block_private.clone(),
            allowed_cidrs: self.allowed_cidrs.clone(),
            egress_rules: self.egress_rules.clone(),
            dns: self.dns,
            dns_options: self.dns_options.clone(),
            shm_size: self.shm_size.clone(),
            network_name: self.network_name.clone(),
            guest_subnet: self.guest_subnet.clone(),
        }
    }

    /// Record checks that need the whole machine but no new state (the
    /// placeholders minted by [`Self::to_record`]).
    fn unrecorded_record_checks(&self) -> Result<()> {
        let mut record = VmRecord::new(
            String::new(),
            self.cpus,
            self.mem,
            Vec::new(),
            Vec::new(),
            self.net,
        );
        record.image = self.image.clone();
        record.remote_volumes = self.remote_volumes.clone();
        record.allowed_cidrs = self.allowed_cidrs.clone();
        record.egress_rules = self.egress_rules.clone();
        record.block_private = self.block_private.clone();
        record.dns_filter_hosts = self.allowed_hosts.clone();
        record.network_name = self.network_name.clone();
        record.guest_subnet = self.guest_subnet.clone();
        record.network_backend = self.network_backend;
        record.set_port_mappings(&self.ports);
        record.credential_policy = self.credentials.clone();
        record.validate_remote_volumes()
    }

    /// Whether credential values come from the caller rather than from this
    /// host's environment.
    fn credentials_supplied_by_api(&self) -> bool {
        self.credentials_supplied_only
            || self.caller == Caller::Api
            || self
                .restored
                .as_ref()
                .is_some_and(|restored| restored.credentials_from_artifact)
    }

    /// The machine record for `name`, with every resolved setting. Provenance
    /// a path learns while preparing disks (the pack it extracted, a host
    /// image it fetched) is the caller's to add.
    pub fn to_record(&self, name: &str) -> Result<VmRecord> {
        crate::data::validate_vm_name(name, "machine name")
            .map_err(|reason| Error::config("create machine", reason))?;
        // Destructured without `..`, like `resolve`.
        let ResolvedSpec {
            caller: _,
            image,
            entrypoint,
            cmd,
            env,
            workdir,
            user,
            init,
            secret_refs,
            restart,
            health_cmd,
            health_interval_secs,
            health_timeout_secs,
            health_retries,
            health_startup_grace_secs,
            stop_on_exit,
            stop_signal,
            stop_timeout_secs,
            shm_size,
            cpus,
            mem,
            storage_gb,
            overlay_gb,
            block_io,
            disk_durability,
            disks,
            cache_disk,
            mounts,
            remote_volumes,
            disk_volumes,
            net,
            network_backend,
            dns,
            dns_options,
            network_name,
            guest_subnet,
            ports,
            allowed_cidrs,
            allowed_hosts,
            block_private,
            egress_rules,
            credentials,
            // Read through `credentials_supplied_by_api` below.
            credentials_supplied_only: _,
            published_sockets,
            gpu,
            gpu_vram_mib,
            rosetta,
            nested_virt,
            cuda,
            docker_socket,
            ssh_agent,
            forkable,
            cuda_fork_pool_size,
            cuda_vram_limit_mib,
            keep_identity,
            ephemeral,
            detached,
            runtime_managed,
            labels,
            restored,
        } = self.clone();
        let restored = restored.unwrap_or_default();
        let is_restore = self.restored.is_some();
        let (mounts, staged_mounts) = HostMount::split_storage_tuples(&mounts);
        let (ports, udp_ports) = PortMapping::split_tuples(&ports);
        let credential_placeholders = match credentials.as_ref() {
            // A restored workload already holds its placeholders.
            Some(_) if is_restore => restored.credential_placeholders,
            Some(policy) => crate::credentials::prepare_policy(policy, allowed_hosts.as_deref())?,
            None => BTreeMap::new(),
        };
        let credentials_supplied_by_api =
            credentials.is_some() && self.credentials_supplied_by_api();
        // Every record field, named, so a new one has to be decided here.
        Ok(VmRecord {
            name: name.to_string(),
            created_at: crate::util::current_timestamp(),
            state: RecordState::Created,
            pause_reason: None,
            paused_checkpoint: None,
            pid: None,
            pid_start_time: None,
            engine_build: None,
            cpus,
            mem,
            block_io,
            disk_durability,
            disks,
            cache_disk,
            disk_volumes,
            block_private,
            mounts,
            staged_mounts,
            staged_mounts_detached_from: None,
            ports,
            udp_ports,
            published_sockets,
            network: net,
            gpu: gpu.then_some(true),
            nested_virt: nested_virt.then_some(true),
            gpu_vram_mib,
            rosetta: rosetta.then_some(true),
            restart,
            last_exit_code: None,
            init,
            // A restored guest already ran its first start.
            init_completed: is_restore,
            remote_volumes,
            env,
            secret_refs,
            workdir,
            user,
            storage_gb,
            overlay_gb,
            allowed_cidrs,
            egress_rules,
            network_backend,
            dns,
            dns_options,
            shm_size,
            network_name,
            guest_subnet,
            image,
            entrypoint,
            cmd,
            labels,
            health_cmd,
            health_interval_secs,
            health_timeout_secs,
            health_retries,
            health_startup_grace_secs,
            ssh_agent,
            cuda,
            forkable,
            detached,
            keep_identity,
            stop_on_exit,
            stop_signal,
            stop_timeout_secs,
            cuda_fork_pool_size,
            cuda_vram_limit_mib,
            cuda_preload_modules: false,
            docker_socket,
            dns_filter_hosts: allowed_hosts,
            credential_policy: credentials,
            external_interceptor_required: restored.mediated_egress_required,
            mediated_egress_required: restored.mediated_egress_required,
            credential_placeholders,
            credentials_supplied_by_api,
            ephemeral,
            source_smolmachine: None,
            packed_image_on_storage: false,
            source_registry_ref: None,
            image_origin: None,
            image_origin_digest: None,
            golden: None,
            fork_generation: None,
            fork_lineage_pid_start_time: None,
            checkpoint_head: restored.checkpoint_head,
            agent_rootfs_digest: None,
            agent_rootfs_path: None,
            fork_overlay_owner: restored.overlay_owner,
            // A restore establishes its own UID lineage under its own name.
            host_uid_owner: is_restore.then(|| name.to_string()),
            forkpoint_held: false,
            fork_env: Vec::new(),
            runtime_managed,
        })
    }
}

#[cfg(test)]
mod tests;
