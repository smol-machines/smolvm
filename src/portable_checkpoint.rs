//! Portable live-checkpoint compatibility and installation.
//!
//! A `.smolcheckpoint` uses the ordinary pack container for files and disks,
//! plus a durable libkrun memory/device snapshot. The container can be copied
//! anywhere; live state is restored only under a versioned, fail-closed runtime
//! compatibility contract.

use crate::config::{RecordState, SmolvmConfig, VmRecord};
use crate::{Error, Result};
use imago::file::File as ImagoFile;
use imago::qcow2::Qcow2;
use imago::{FormatDriverBuilder, PermissiveImplicitOpenGate};
use sha2::{Digest, Sha256};
use smolvm_pack::assets::AssetCollector;
use smolvm_pack::format::{
    CheckpointAsset, CheckpointCpuContract, CheckpointDisk, CheckpointDiskFile, CheckpointNetwork,
    CheckpointPort, CheckpointWorkload, PackManifest, PackMode, PortableCheckpointManifest,
};
use smolvm_pack::packer::Packer;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Current portable-checkpoint metadata version.
pub const FORMAT_VERSION: u32 = 4;
/// libkrun VM/vCPU/device-state compatibility identifier.
pub const RUNTIME_ABI: &str = "libkrun-portable-snapshot-v1";
/// Device topology supported by the initial portable checkpoint profile.
pub const DEVICE_PROFILE: &str = "smolvm-basic-v1";
/// Directory inside an extracted artifact containing live state.
pub const ASSET_DIR: &str = "checkpoint";

const INSTALLED_DIR: &str = "portable-checkpoint";
const PENDING_MARKER: &str = "pending";
const RETAINED_MEMORY_BACKING: &str = ".portable-checkpoint-memory.bin";

/// Optional host paths used while building a portable checkpoint artifact.
#[derive(Debug, Clone, Default)]
pub struct CaptureOptions {
    /// Disk-backed directory used for the temporary, uncompressed image.
    pub staging_dir: Option<PathBuf>,
    /// Directory containing libkrun and libkrunfw.
    pub lib_dir: Option<PathBuf>,
    /// Directory containing the guest agent root filesystem.
    pub rootfs_dir: Option<PathBuf>,
}

/// Timings and size returned by a completed portable checkpoint capture.
#[derive(Debug, Clone)]
pub struct CaptureResult {
    /// Compressed artifact size in bytes.
    pub size_bytes: u64,
    /// Time for which the source's vCPUs and disks were frozen.
    pub source_pause: std::time::Duration,
    /// Complete capture and compression time.
    pub elapsed: std::time::Duration,
}

/// Restore a portable live checkpoint into a new stopped machine record.
///
/// The restored machine preserves the checkpoint's CPU, memory, disks,
/// workload, and network topology. Its first start resumes the captured live
/// state, and the machine remains checkpointable so it can immediately serve
/// as a reusable rollback/fork root.
pub fn restore_from_path(db: &crate::db::SmolvmDb, name: &str, artifact: &Path) -> Result<()> {
    crate::data::validate_vm_name(name, "machine name")
        .map_err(|reason| Error::config("restore checkpoint", reason))?;
    if !artifact.is_file() {
        return Err(Error::config(
            "restore checkpoint",
            format!("file not found: {}", artifact.display()),
        ));
    }

    let manifest = smolvm_pack::packer::read_manifest_from_sidecar(artifact)
        .map_err(|error| Error::agent("read checkpoint manifest", error.to_string()))?;
    let checkpoint = manifest.checkpoint.as_ref().ok_or_else(|| {
        Error::config(
            "restore checkpoint",
            format!("{} is not a .smolcheckpoint artifact", artifact.display()),
        )
    })?;
    validate_compatibility(checkpoint)?;
    crate::platform::ensure_artifact_arch_matches_host(&manifest.platform)?;

    // Reserve the name before touching its data directory. SDKs and CLIs may
    // run in separate processes, so a process-local lifecycle mutex is not a
    // sufficient creation boundary.
    let token = crate::db::SmolvmDb::create_reservation_token();
    if !db.reserve_vm_create(name, &token)? {
        return Err(Error::agent_conflict(
            "restore checkpoint",
            format!("machine '{name}' already exists or is being created"),
        ));
    }
    let mut reservation = RestoreReservation {
        db: db.clone(),
        name: name.to_string(),
        token,
        committed: false,
    };

    let record = restored_record(name, &manifest, checkpoint)?;
    let footer = smolvm_pack::packer::read_footer_from_sidecar(artifact)
        .map_err(|error| Error::agent("read checkpoint footer", error.to_string()))?;
    let vm_data = crate::agent::vm_data_dir(name);
    let cache_dir = crate::agent::machine_layers_cache_dir(name);
    let result = (|| -> Result<()> {
        let _manager = crate::agent::AgentManager::for_vm_with_sizes(
            name,
            checkpoint.storage_gib,
            checkpoint.overlay_gib,
        )?;
        smolvm_pack::extract::force_detach_layers_volume(&cache_dir);
        match std::fs::remove_dir_all(&cache_dir) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(Error::agent(
                    "clear checkpoint extraction",
                    error.to_string(),
                ));
            }
        }
        smolvm_pack::extract::extract_sidecar(artifact, &cache_dir, &footer, false, false)
            .map_err(|error| Error::agent("extract checkpoint", error.to_string()))?;
        install(&cache_dir, &vm_data, checkpoint)?;
        discard_transport_pack(&vm_data)?;
        if !reservation
            .db
            .commit_reserved_vm(name, &reservation.token, &record)?
        {
            return Err(Error::agent_conflict(
                "restore checkpoint",
                format!("machine '{name}' is no longer reserved"),
            ));
        }
        reservation.committed = true;
        Ok(())
    })();
    smolvm_pack::extract::force_detach_layers_volume(&cache_dir);
    if let Err(error) = result {
        if let Err(remove_error) = std::fs::remove_dir_all(&vm_data) {
            if remove_error.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(
                    machine = %name,
                    error = %remove_error,
                    "failed to clean checkpoint restore after error"
                );
            }
        }
        return Err(error);
    }
    Ok(())
}

struct RestoreReservation {
    db: crate::db::SmolvmDb,
    name: String,
    token: String,
    committed: bool,
}

impl Drop for RestoreReservation {
    fn drop(&mut self) {
        if !self.committed {
            if let Err(error) = self
                .db
                .release_vm_create_reservation(&self.name, &self.token)
            {
                tracing::warn!(
                    machine = %self.name,
                    %error,
                    "failed to release checkpoint restore reservation"
                );
            }
        }
    }
}

fn restored_record(
    name: &str,
    manifest: &PackManifest,
    checkpoint: &PortableCheckpointManifest,
) -> Result<VmRecord> {
    let network = checkpoint.network.as_ref();
    let mut record = VmRecord::new(
        name.to_string(),
        checkpoint.cpus,
        checkpoint.memory_mib,
        Vec::new(),
        network
            .into_iter()
            .flat_map(|network| network.ports.iter())
            .map(|port| (port.host, port.guest))
            .collect(),
        network.is_some_and(|network| network.enabled),
    );
    record.storage_gb = checkpoint.storage_gib;
    record.overlay_gb = checkpoint.overlay_gib;
    record.allowed_cidrs = network.and_then(|network| network.allowed_cidrs.clone());
    record.dns_filter_hosts = network.and_then(|network| network.dns_filter_hosts.clone());
    record.network_backend = restored_network_backend(checkpoint)?;
    record.dns = network
        .and_then(|network| network.dns.as_deref())
        .map(str::parse)
        .transpose()
        .map_err(|error: std::net::AddrParseError| {
            Error::config("restore checkpoint DNS", error.to_string())
        })?;
    record.network_name = network.and_then(|network| network.network_name.clone());
    record.entrypoint = manifest.entrypoint.clone();
    record.cmd = manifest.cmd.clone();
    record.env = crate::util::parse_env_list(&manifest.env);
    record.workdir = manifest.workdir.clone();
    record.secret_refs = manifest.secret_refs.clone();
    for (key, reference) in &record.secret_refs {
        crate::secrets::validate_ref(reference, crate::secrets::ResolutionScope::Untrusted)
            .map_err(|error| {
                Error::config(
                    "restore checkpoint",
                    format!("secret '{key}': {error} (checkpoints may not carry host secret refs)"),
                )
            })?;
    }
    if let Some(workload) = &checkpoint.workload {
        record.image = Some(workload.image.clone());
        record.user = workload.user.clone();
        record.fork_overlay_owner = Some(workload.overlay_owner.clone());
        record.restart.policy = workload
            .restart_policy
            .parse()
            .map_err(|error: String| Error::config("restore checkpoint restart policy", error))?;
        record.restart.max_retries = workload.restart_max_retries;
        record.restart.max_backoff_secs = workload.restart_max_backoff_secs;
    }
    // The live guest already contains the initialized workload. Re-running
    // image pull/init on its first start would duplicate side effects.
    record.init_completed = true;
    record.forkable = true;
    Ok(record)
}

struct SavedVmPause {
    control: PathBuf,
    armed: bool,
}

impl SavedVmPause {
    fn resume(&mut self) -> Result<()> {
        if !self.armed {
            return Ok(());
        }
        let reply = crate::agent::fork::control_socket_cmd(&self.control, "RESUME")?;
        if !reply.starts_with("OK") {
            return Err(Error::agent(
                "resume checkpoint source",
                format!("libkrun returned: {reply}"),
            ));
        }
        self.armed = false;
        Ok(())
    }
}

impl Drop for SavedVmPause {
    fn drop(&mut self) {
        if self.armed {
            match crate::agent::fork::control_socket_cmd(&self.control, "RESUME") {
                Ok(reply) if reply.starts_with("OK") => {}
                Ok(reply) => tracing::warn!(%reply, "failed to resume checkpoint source"),
                Err(error) => tracing::warn!(%error, "failed to resume checkpoint source"),
            }
        }
    }
}

fn staging_root(options: &CaptureOptions) -> Result<PathBuf> {
    let root = options
        .staging_dir
        .clone()
        .or_else(|| std::env::var_os("SMOLVM_PACK_STAGING").map(PathBuf::from))
        .or_else(|| dirs::cache_dir().map(|cache| cache.join("smolvm")))
        .unwrap_or_else(std::env::temp_dir);
    std::fs::create_dir_all(&root)
        .map_err(|error| Error::agent("create checkpoint staging root", error.to_string()))?;
    Ok(root)
}

fn checkpoint_lib_dir(options: &CaptureOptions) -> Result<PathBuf> {
    options
        .lib_dir
        .clone()
        .or_else(crate::agent::find_lib_dir)
        .ok_or_else(|| {
            Error::agent(
                "find checkpoint runtime libraries",
                "could not find libkrun; set SMOLVM_LIB_DIR",
            )
        })
}

fn checkpoint_rootfs_dir(options: &CaptureOptions) -> Result<PathBuf> {
    let candidates = [
        options.rootfs_dir.clone(),
        std::env::var_os("SMOLVM_AGENT_ROOTFS").map(PathBuf::from),
        dirs::data_dir().map(|dir| dir.join("smolvm/agent-rootfs")),
        std::env::current_exe()
            .ok()
            .and_then(|path| path.parent().map(|dir| dir.join("agent-rootfs"))),
    ];
    candidates
        .into_iter()
        .flatten()
        .find(|candidate| std::fs::symlink_metadata(candidate.join("sbin/init")).is_ok())
        .ok_or_else(|| {
            Error::agent(
                "find checkpoint agent rootfs",
                "could not find agent rootfs; set SMOLVM_AGENT_ROOTFS",
            )
        })
}

fn validated_capture_source(name: &str) -> Result<SmolvmConfig> {
    let config = SmolvmConfig::load()?;
    let vm = config
        .vms
        .get(name)
        .ok_or_else(|| Error::vm_not_found(name))?;
    if crate::agent::state_probe::resolve_state(name, vm) != RecordState::Running {
        return Err(Error::agent_conflict(
            "checkpoint machine",
            format!("machine '{name}' must be running"),
        ));
    }
    validate_capture_profile(vm)?;

    let control = crate::agent::fork::control_socket_path(name);
    let status = crate::agent::fork::control_socket_cmd(&control, "STATUS").map_err(|error| {
        Error::agent_conflict(
            "checkpoint machine",
            format!(
                "machine '{name}' has no checkpoint control socket ({error}); start it with --forkable"
            ),
        )
    })?;
    if status.trim() != "OK running" {
        return Err(Error::agent_conflict(
            "checkpoint machine",
            format!("machine '{name}' is not checkpointable: {status}"),
        ));
    }
    Ok(config)
}

/// Capture a running checkpointable machine into a self-contained artifact.
///
/// The source is paused only while libkrun saves execution state and the exact
/// disk chains are cloned. Hashing and compression continue after it resumes.
pub fn capture_to_path(
    name: &str,
    output: &Path,
    options: &CaptureOptions,
) -> Result<CaptureResult> {
    let started = std::time::Instant::now();
    if output
        .extension()
        .is_none_or(|extension| !extension.eq_ignore_ascii_case("smolcheckpoint"))
    {
        return Err(Error::config(
            "checkpoint machine",
            "output must end in .smolcheckpoint",
        ));
    }
    if output.exists() {
        return Err(Error::config(
            "checkpoint machine",
            format!("refusing to overwrite {}", output.display()),
        ));
    }

    // Fail before staging runtime assets when the source is already known to
    // be ineligible. The source is revalidated under the cross-process lock
    // immediately before capture so this fast preflight is never trusted for
    // the consistency boundary.
    let _ = validated_capture_source(name)?;

    let temp_dir = tempfile::Builder::new()
        .prefix("checkpoint-staging-")
        .tempdir_in(staging_root(options)?)
        .map_err(|error| Error::agent("create checkpoint staging", error.to_string()))?;
    let staging_dir = temp_dir.path().join("staging");
    let mut collector = AssetCollector::new(staging_dir.clone())
        .map_err(|error| Error::agent("collect checkpoint assets", error.to_string()))?;
    collector
        .collect_libraries(&checkpoint_lib_dir(options)?)
        .map_err(|error| Error::agent("collect checkpoint libraries", error.to_string()))?;
    collector
        .collect_agent_rootfs(&checkpoint_rootfs_dir(options)?)
        .map_err(|error| Error::agent("collect checkpoint rootfs", error.to_string()))?;
    collector
        .create_storage_template()
        .map_err(|error| Error::agent("create checkpoint storage template", error.to_string()))?;

    // A serve process has its own lifecycle mutex, but another CLI process
    // does not share it. Use the same source lock as `machine fork` so SAVE and
    // fork can never overlap or produce two competing source generations.
    // Release it as soon as the source resumes; hashing and compression do not
    // touch the live machine and must not delay a subsequent fork.
    let source_lock = crate::agent::fork::lock_fork_source(name)?;
    let config = validated_capture_source(name)?;
    let vm = config
        .vms
        .get(name)
        .expect("validated checkpoint source must remain in its loaded config");
    let control = crate::agent::fork::control_socket_path(name);
    crate::agent::fork::sync_fork_source(name)?;
    let snapshot_dir = staging_dir.join(ASSET_DIR);
    let pause_started = std::time::Instant::now();
    let reply = crate::agent::fork::control_socket_cmd_with_timeout(
        &control,
        &format!("SAVE {}", snapshot_dir.display()),
        std::time::Duration::from_secs(30 * 60),
    )?;
    if !reply.starts_with("OK") {
        return Err(Error::agent(
            "checkpoint machine",
            format!("libkrun save failed: {reply}"),
        ));
    }
    let mut pause = SavedVmPause {
        control,
        armed: true,
    };
    let checkpoint_disks = stage_disk_chains(&crate::agent::vm_data_dir(name), &snapshot_dir)?;
    pause.resume()?;
    let source_pause = pause_started.elapsed();
    drop(source_lock);

    let assets = crate::pack_export::FromVmAssets {
        mode: PackMode::Vm,
        image: None,
        image_env: Vec::new(),
        layer_bytes: 0,
    };
    let platform = format!("linux/{}", crate::platform::Arch::current().oci_arch());
    let host_platform = crate::platform::Platform::current()
        .host_oci_platform()
        .to_string();
    let mut manifest = PackManifest::new(
        format!("vm://{name}"),
        "none".to_string(),
        platform,
        host_platform.clone(),
    );
    crate::pack_export::seed_manifest_from_vm(&mut manifest, vm, &assets);
    // A normal VM-mode pack supplies `/bin/sh` when the source has no explicit
    // entrypoint because it packages a flattened rootfs. A live checkpoint must
    // preserve the exact OCI launch vector instead: injecting `/bin/sh` turns a
    // valid `python3 ...` workload into the invalid `/bin/sh python3 ...` after
    // the restored machine's first ordinary cold restart.
    manifest.entrypoint = vm.entrypoint.clone();
    manifest.cpus = vm.cpus;
    manifest.mem = vm.mem;
    manifest.checkpoint = Some(PortableCheckpointManifest {
        version: FORMAT_VERSION,
        runtime_abi: RUNTIME_ABI.to_string(),
        host_platform,
        cpu_contract: checkpoint_cpu_contract()?,
        cpus: vm.cpus,
        memory_mib: vm.mem,
        // Persist the effective sizes, not the optional user overrides. This
        // keeps the artifact self-describing if runtime defaults change before
        // it is restored on another host.
        storage_gib: Some(
            vm.storage_gb
                .unwrap_or(crate::storage::DEFAULT_STORAGE_SIZE_GIB),
        ),
        overlay_gib: Some(
            vm.overlay_gb
                .unwrap_or(crate::storage::DEFAULT_OVERLAY_SIZE_GIB),
        ),
        device_profile: DEVICE_PROFILE.to_string(),
        state: describe_asset(
            &snapshot_dir.join("checkpoint.bin"),
            "checkpoint/checkpoint.bin",
        )?,
        // Guest RAM is a sparse logical image and may be many GiB even when
        // very little is resident. The pack container verifies its compressed
        // bytes; hashing the expanded holes again makes import scale with the
        // configured RAM limit instead of the checkpoint's physical size.
        memory: describe_sparse_asset(&snapshot_dir.join("memory.bin"), "checkpoint/memory.bin")?,
        layout: describe_asset(
            &snapshot_dir.join("manifest.bin"),
            "checkpoint/manifest.bin",
        )?,
        disks: checkpoint_disks,
        workload: checkpoint_workload(name, vm),
        network: Some(checkpoint_network(vm)),
    });
    manifest.assets = collector.into_inventory();

    let collector = AssetCollector::new(staging_dir)
        .map_err(|error| Error::agent("collect checkpoint assets", error.to_string()))?;
    let info = Packer::new(manifest)
        .with_asset_collector(collector)
        .pack_artifact(output)
        .map_err(|error| Error::agent("pack checkpoint", error.to_string()))?;
    Ok(CaptureResult {
        size_bytes: info.total_size,
        source_pause,
        elapsed: started.elapsed(),
    })
}

fn checkpoint_workload(name: &str, vm: &VmRecord) -> Option<CheckpointWorkload> {
    vm.image.as_ref().map(|image| CheckpointWorkload {
        image: image.clone(),
        user: vm.user.clone(),
        overlay_owner: crate::workload::persistent_overlay_owner_with_lineage(
            name,
            vm.golden.as_deref(),
            vm.fork_overlay_owner.as_deref(),
        ),
        restart_policy: vm.restart.policy.to_string(),
        restart_max_retries: vm.restart.max_retries,
        restart_max_backoff_secs: vm.restart.max_backoff_secs,
    })
}

/// Return the strict host CPU feature fingerprint used for snapshot matching.
pub fn cpu_fingerprint() -> Result<String> {
    let mut identity = format!(
        "platform={}\n",
        crate::platform::Platform::current().host_oci_platform()
    );
    #[cfg(target_os = "linux")]
    {
        let cpuinfo = std::fs::read_to_string("/proc/cpuinfo")
            .map_err(|error| Error::agent("fingerprint CPU", error.to_string()))?;
        let accepted = [
            "vendor_id",
            "cpu family",
            "model",
            "stepping",
            "flags",
            "Features",
            "CPU implementer",
            "CPU architecture",
            "CPU variant",
            "CPU part",
            "CPU revision",
        ];
        for line in cpuinfo.lines().take_while(|line| !line.trim().is_empty()) {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            if accepted.contains(&key.trim()) {
                identity.push_str(key.trim());
                identity.push('=');
                identity.push_str(
                    value
                        .split_whitespace()
                        .collect::<Vec<_>>()
                        .join(" ")
                        .as_str(),
                );
                identity.push('\n');
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("sysctl")
            .args(["-n", "machdep.cpu.brand_string", "hw.model"])
            .output()
            .map_err(|error| Error::agent("fingerprint CPU", error.to_string()))?;
        if !output.status.success() {
            return Err(Error::agent(
                "fingerprint CPU",
                String::from_utf8_lossy(&output.stderr).trim().to_string(),
            ));
        }
        identity.push_str(&String::from_utf8_lossy(&output.stdout));
    }
    #[cfg(target_os = "windows")]
    {
        identity.push_str(&std::env::var("PROCESSOR_IDENTIFIER").unwrap_or_default());
        identity.push('\n');
        identity.push_str(&std::env::var("PROCESSOR_ARCHITECTURE").unwrap_or_default());
    }
    Ok(hex::encode(Sha256::digest(identity.as_bytes())))
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn linux_cpu_vendor(cpuinfo: &str) -> Option<String> {
    cpuinfo
        .lines()
        .take_while(|line| !line.trim().is_empty())
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            (key.trim() == "vendor_id")
                .then(|| value.trim().to_string())
                .filter(|vendor| !vendor.is_empty() && vendor.len() <= 64)
        })
}

fn cpu_vendor() -> Result<Option<String>> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        let cpuinfo = std::fs::read_to_string("/proc/cpuinfo")
            .map_err(|error| Error::agent("identify CPU vendor", error.to_string()))?;
        Ok(linux_cpu_vendor(&cpuinfo))
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        Ok(None)
    }
}

/// Architectural features a guest on this aarch64 host can use, by name.
///
/// The guest sees the host's own ID registers, so the host's feature set is the
/// guest's feature set — with one deliberate subtraction: libkrun masks SME out
/// of `ID_AA64PFR1_EL1` before the guest runs, because a guest that sees SME
/// "will break after enabling the MMU". Anything SME is therefore invisible to
/// the guest on every host and must not enter the contract, or checkpoints would
/// be refused over a feature no guest can reach.
///
/// Names are the ARM `FEAT_*` identifiers, which both platforms already speak:
/// macOS publishes them through `sysctl hw.optional.arm.*`, Linux through the
/// `Features` line in `/proc/cpuinfo`.
#[cfg(target_arch = "aarch64")]
fn aarch64_guest_features() -> Result<Vec<String>> {
    let mut features = collect_aarch64_host_features()?;
    features.retain(|name| !is_masked_from_guest(name));
    features.sort();
    features.dedup();
    Ok(features)
}

/// Features the VMM removes before the guest ever sees them. Keep in step with
/// libkrun's vCPU setup.
#[cfg(any(target_arch = "aarch64", test))]
#[allow(dead_code)]
fn is_masked_from_guest(name: &str) -> bool {
    // libkrun: `val & !AA64PFR1_EL1_SMEMASK`. Covers FEAT_SME, FEAT_SME2 and
    // every SME_* sub-feature.
    name.contains("SME")
}

#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
fn collect_aarch64_host_features() -> Result<Vec<String>> {
    let output = std::process::Command::new("sysctl")
        .arg("-a")
        .output()
        .map_err(|error| Error::agent("read CPU features", error.to_string()))?;
    if !output.status.success() {
        return Err(Error::agent(
            "read CPU features",
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }
    Ok(parse_macos_features(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

/// Pull the enabled `FEAT_*` names out of `sysctl -a`.
///
/// macOS reports one line per feature, `hw.optional.arm.FEAT_X: 1`, where 0
/// means the silicon lacks it. Separated from the command so the parsing is
/// testable against recorded output from real machines.
// The two parsers below are pure string functions. They are compiled on every
// aarch64 host and under `cfg(test)` everywhere, so macOS CI exercises the Linux
// parser and vice versa; each is used by exactly one OS at runtime, hence the
// dead-code allowance.
#[cfg(any(target_arch = "aarch64", test))]
#[allow(dead_code)]
fn parse_macos_features(sysctl_output: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in sysctl_output.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let Some(name) = key.trim().strip_prefix("hw.optional.arm.") else {
            continue;
        };
        if value.trim() == "1" && !name.is_empty() {
            out.push(name.to_string());
        }
    }
    out
}

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
fn collect_aarch64_host_features() -> Result<Vec<String>> {
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo")
        .map_err(|error| Error::agent("read CPU features", error.to_string()))?;
    Ok(parse_linux_features(&cpuinfo))
}

/// Pull the HWCAP names out of `/proc/cpuinfo`'s `Features` line.
///
/// Linux prints lowercase HWCAP tokens (`asimd`, `bf16`, `i8mm`) rather than
/// ARM's `FEAT_*` spelling, so they are normalised to a common form. Only the
/// first processor block is read: every core in a machine smolvm will run on
/// presents the same features.
#[cfg(any(target_arch = "aarch64", test))]
#[allow(dead_code)]
fn parse_linux_features(cpuinfo: &str) -> Vec<String> {
    for line in cpuinfo.lines().take_while(|line| !line.trim().is_empty()) {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if key.trim() != "Features" {
            continue;
        }
        return value
            .split_whitespace()
            .map(|token| format!("FEAT_{}", token.to_ascii_uppercase()))
            .collect();
    }
    Vec::new()
}

fn checkpoint_cpu_contract() -> Result<CheckpointCpuContract> {
    if cpu_vendor()?.as_deref() == Some("GenuineIntel") {
        return Ok(CheckpointCpuContract::LinuxKvmIntelPortableV1);
    }
    #[cfg(target_arch = "aarch64")]
    {
        return Ok(CheckpointCpuContract::Aarch64FeaturesV1 {
            features: aarch64_guest_features()?,
        });
    }
    #[allow(unreachable_code)]
    Ok(CheckpointCpuContract::ExactV1 {
        fingerprint: cpu_fingerprint()?,
    })
}

/// Accept a checkpoint whose recorded features this host also provides.
///
/// A superset is enough: extra features on the destination are harmless, since
/// the guest already decided at boot what it would use. Anything missing is
/// named, because "does not match this host" gives an operator nothing to act
/// on, while "missing FEAT_BF16, FEAT_I8MM" says which machines can take it.
///
/// Note this is a genuine set comparison, not a generation ordering. Newer
/// silicon is not automatically a superset: an M4 Max provides twenty features
/// an M1 Pro lacks, yet lacks FEAT_SSBS that the M1 Pro has, so neither
/// direction is safe between them and both are correctly refused.
#[cfg(target_arch = "aarch64")]
fn validate_aarch64_features(required: &[String]) -> Result<()> {
    let available = aarch64_guest_features()?;
    let missing = missing_features(required, &available);
    if missing.is_empty() {
        return Ok(());
    }
    Err(Error::agent(
        "restore checkpoint",
        format!(
            "this host does not provide {} the checkpoint's guest was given: {}",
            if missing.len() == 1 {
                "a CPU feature"
            } else {
                "CPU features"
            },
            missing.join(", ")
        ),
    ))
}

/// On a non-aarch64 host an aarch64 feature contract can never be satisfied;
/// the architecture check upstream already refuses it, so this only keeps the
/// match exhaustive.
#[cfg(not(target_arch = "aarch64"))]
fn validate_aarch64_features(_required: &[String]) -> Result<()> {
    Err(Error::agent(
        "restore checkpoint",
        "checkpoint requires an aarch64 host",
    ))
}

/// Recorded features this host does not provide. Pure, so the comparison is
/// testable against feature sets captured from real machines.
///
/// Gated to match its only caller — the aarch64 validator — plus tests, so a
/// non-aarch64 cross build does not see it as dead code.
#[cfg(any(target_arch = "aarch64", test))]
#[allow(dead_code)]
fn missing_features(required: &[String], available: &[String]) -> Vec<String> {
    let have: std::collections::HashSet<&str> = available.iter().map(String::as_str).collect();
    required
        .iter()
        .filter(|name| !have.contains(name.as_str()))
        .cloned()
        .collect()
}

fn validate_cpu_compatibility(checkpoint: &PortableCheckpointManifest) -> Result<()> {
    match &checkpoint.cpu_contract {
        CheckpointCpuContract::ExactV1 { fingerprint } => {
            if fingerprint == &cpu_fingerprint()? {
                return Ok(());
            }
            return Err(Error::agent(
                "restore checkpoint",
                "checkpoint CPU feature contract does not match this host",
            ));
        }
        CheckpointCpuContract::Aarch64FeaturesV1 { features } => {
            return validate_aarch64_features(features);
        }
        CheckpointCpuContract::LinuxKvmIntelPortableV1 => {
            let current_vendor = cpu_vendor()?.ok_or_else(|| {
                Error::agent(
                    "restore checkpoint",
                    "checkpoint CPU contract requires Linux KVM on x86_64",
                )
            })?;
            if current_vendor != "GenuineIntel" {
                return Err(Error::agent(
                    "restore checkpoint",
                    format!("checkpoint requires an Intel KVM host, found '{current_vendor}'"),
                ));
            }
        }
    }

    // The durable vCPU state contains the exact guest CPUID and MSR contract.
    // KVM validates those values when libkrun applies the checkpoint, so a
    // destination missing any required architectural feature still fails
    // closed even though host model/stepping differences are accepted here.
    Ok(())
}

/// Reject host-bound device state that cannot yet be resumed from an artifact.
pub fn validate_capture_profile(vm: &VmRecord) -> Result<()> {
    let mut unsupported = Vec::new();
    if !vm.mounts.is_empty() || !vm.staged_mounts.is_empty() {
        unsupported.push("host mounts");
    }
    if !vm.published_sockets.is_empty() {
        unsupported.push("published sockets");
    }
    if !vm.remote_volumes.is_empty() {
        unsupported.push("remote volumes");
    }
    if !vm.secret_refs.is_empty() {
        unsupported.push("host secret references");
    }
    if vm.source_smolmachine.is_some()
        || vm
            .image
            .as_deref()
            .and_then(crate::data::image_source::packed_layers_dir_for_ref)
            .is_some()
    {
        unsupported.push("host-backed image layers");
    }
    if vm.dns.is_some() {
        unsupported.push("custom DNS");
    }
    if vm.network_name.is_some() {
        unsupported.push("named inter-VM networking");
    }
    if vm.gpu.unwrap_or(false) {
        unsupported.push("Vulkan GPU state");
    }
    if vm.cuda {
        unsupported.push("CUDA state");
    }
    if vm.rosetta.unwrap_or(false) {
        unsupported.push("Rosetta");
    }
    if vm.ssh_agent {
        unsupported.push("SSH agent forwarding");
    }
    if vm.docker_socket {
        unsupported.push("Docker socket forwarding");
    }
    if unsupported.is_empty() {
        return Ok(());
    }
    Err(Error::config(
        "checkpoint machine",
        format!(
            "the initial portable checkpoint profile does not support {}; stop or detach these resources before capture",
            unsupported.join(", ")
        ),
    ))
}

/// Parse the effective network backend persisted by a version-two checkpoint.
pub fn restored_network_backend(
    checkpoint: &PortableCheckpointManifest,
) -> Result<Option<crate::network::NetworkBackend>> {
    let Some(label) = checkpoint
        .network
        .as_ref()
        .and_then(|network| network.backend.as_deref())
    else {
        return Ok(None);
    };
    match label {
        "tsi" => Ok(Some(crate::network::NetworkBackend::Tsi)),
        "virtio-net" => Ok(Some(crate::network::NetworkBackend::VirtioNet)),
        other => Err(Error::agent(
            "restore checkpoint",
            format!("checkpoint uses unknown network backend '{other}'"),
        )),
    }
}

fn checkpoint_network(vm: &VmRecord) -> CheckpointNetwork {
    let effective = crate::network::plan_launch_network(
        &vm.vm_resources(),
        vm.dns_filter_hosts.as_deref(),
        vm.ports.len(),
    );
    let backend = match effective.backend {
        crate::network::EffectiveNetworkBackend::None => None,
        crate::network::EffectiveNetworkBackend::Tsi => Some("tsi".to_string()),
        crate::network::EffectiveNetworkBackend::VirtioNet => Some("virtio-net".to_string()),
    };
    CheckpointNetwork {
        enabled: effective.has_network(),
        ports: vm
            .ports
            .iter()
            .map(|(host, guest)| CheckpointPort {
                host: *host,
                guest: *guest,
            })
            .collect(),
        backend,
        dns: vm.dns.map(|dns| dns.to_string()),
        network_name: vm.network_name.clone(),
        allowed_cidrs: vm.allowed_cidrs.clone(),
        dns_filter_hosts: vm.dns_filter_hosts.clone(),
    }
}

fn disk_target(role: &str, index: usize, format: &str) -> Result<String> {
    if index == 0 {
        return match (role, format) {
            ("storage", "qcow2") => Ok("storage.qcow2".to_string()),
            ("storage", "raw") => Ok("storage.raw".to_string()),
            ("overlay", "qcow2") => Ok("overlay.qcow2".to_string()),
            ("overlay", "raw") => Ok("overlay.raw".to_string()),
            _ => Err(Error::agent(
                "checkpoint disk",
                format!("invalid disk role/format {role}/{format}"),
            )),
        };
    }
    if role != "storage" && role != "overlay" {
        return Err(Error::agent(
            "checkpoint disk",
            format!("invalid disk role '{role}'"),
        ));
    }
    if format != "raw" && format != "qcow2" {
        return Err(Error::agent(
            "checkpoint disk",
            format!("invalid disk format '{format}'"),
        ));
    }
    if index >= 64 {
        return Err(Error::agent(
            "checkpoint disk",
            format!("{role} backing chain is too deep"),
        ));
    }
    // Backings live beside the active top layer because qcow2 backing paths
    // are relative to the image that references them. Use an explicit reserved
    // namespace: the earlier single-character names eventually collided with
    // live-fork's `d/` disk-generation directory at deeper lineage depths.
    Ok(format!(".smolcheckpoint-{role}-{index}.{format}"))
}

fn inspect_qcow2(path: &Path) -> Result<(Option<String>, Option<String>)> {
    let qcow = Qcow2::<ImagoFile>::builder_path(path)
        .backing(None)
        .data_file(None)
        // The gate opens only the explicitly supplied top-level path here;
        // backing and external-data auto-open are both disabled above.
        .open_sync(PermissiveImplicitOpenGate::default())
        .map_err(|error| Error::agent("inspect checkpoint qcow2", error.to_string()))?;
    if qcow.requires_external_data_file() {
        return Err(Error::agent(
            "checkpoint disk",
            format!("{} uses an unsupported external data file", path.display()),
        ));
    }
    Ok((
        qcow.implicit_backing_file().cloned(),
        qcow.implicit_backing_format().cloned(),
    ))
}

fn detect_disk_format(path: &Path, declared: Option<&str>) -> Result<&'static str> {
    match declared {
        Some("raw" | "file") => return Ok("raw"),
        Some("qcow2") => return Ok("qcow2"),
        Some(other) => {
            return Err(Error::agent(
                "checkpoint disk",
                format!("unsupported backing format '{other}'"),
            ));
        }
        None => {}
    }
    let mut file = std::fs::File::open(path)
        .map_err(|error| Error::agent("inspect checkpoint disk", error.to_string()))?;
    let mut magic = [0_u8; 4];
    let count = file
        .read(&mut magic)
        .map_err(|error| Error::agent("inspect checkpoint disk", error.to_string()))?;
    Ok(if count == magic.len() && magic == *b"QFI\xfb" {
        "qcow2"
    } else {
        "raw"
    })
}

fn resolve_backing_path(image: &Path, backing: &str) -> PathBuf {
    let backing = PathBuf::from(backing);
    if backing.is_absolute() {
        backing
    } else {
        image
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(backing)
    }
}

fn rewrite_qcow2_backing(path: &Path, backing: &str) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|error| Error::agent("rewrite qcow2 backing", error.to_string()))?;
    let mut header = [0_u8; 20];
    file.read_exact(&mut header)
        .map_err(|error| Error::agent("read qcow2 header", error.to_string()))?;
    if header[..4] != *b"QFI\xfb" {
        return Err(Error::agent(
            "rewrite qcow2 backing",
            format!("{} is not qcow2", path.display()),
        ));
    }
    let offset = u64::from_be_bytes(header[8..16].try_into().unwrap());
    let old_len = u32::from_be_bytes(header[16..20].try_into().unwrap()) as usize;
    if offset == 0 || old_len == 0 || backing.len() > old_len {
        return Err(Error::agent(
            "rewrite qcow2 backing",
            format!(
                "{} cannot replace its {}-byte backing name with {} bytes",
                path.display(),
                old_len,
                backing.len()
            ),
        ));
    }
    let end = offset
        .checked_add(old_len as u64)
        .ok_or_else(|| Error::agent("rewrite qcow2 backing", "header offset overflow"))?;
    if end
        > file
            .metadata()
            .map_err(|e| Error::agent("inspect qcow2", e.to_string()))?
            .len()
    {
        return Err(Error::agent(
            "rewrite qcow2 backing",
            "backing filename lies outside the qcow2 file",
        ));
    }
    file.seek(SeekFrom::Start(offset))
        .and_then(|_| file.write_all(backing.as_bytes()))
        .and_then(|_| file.write_all(&vec![0_u8; old_len - backing.len()]))
        .map_err(|error| Error::agent("rewrite qcow2 backing", error.to_string()))?;
    file.seek(SeekFrom::Start(16))
        .and_then(|_| file.write_all(&(backing.len() as u32).to_be_bytes()))
        .and_then(|_| file.sync_all())
        .map_err(|error| Error::agent("rewrite qcow2 backing", error.to_string()))?;
    Ok(())
}

/// Stage exact, self-contained disk chains without flattening them.
///
/// Each qcow2 layer is copied as-is and rebased to a one-character relative
/// filename. This preserves the block backend's allocation/topology state,
/// avoids multi-gigabyte logical scans, and prevents restored images from
/// retaining absolute references to the capture host.
pub fn stage_disk_chains(
    snapshot_dir: &Path,
    checkpoint_dir: &Path,
) -> Result<Vec<CheckpointDisk>> {
    let mut disks = Vec::new();
    for (role, raw_name) in [
        ("storage", crate::storage::STORAGE_DISK_FILENAME),
        ("overlay", crate::storage::OVERLAY_DISK_FILENAME),
    ] {
        let (mut source, initial_format) = crate::agent::resolve_disk_image(snapshot_dir, raw_name);
        if !source.is_file() {
            continue;
        }
        let mut format = match initial_format {
            crate::data::disk::DiskFormat::Raw => "raw",
            crate::data::disk::DiskFormat::Qcow2 => "qcow2",
        };
        let disk_staging = checkpoint_dir.join("disks").join(role);
        std::fs::create_dir_all(&disk_staging)
            .map_err(|error| Error::agent("stage checkpoint disk", error.to_string()))?;
        let mut files = Vec::new();
        for index in 0..64 {
            let target = disk_target(role, index, format)?;
            let artifact_path = format!("checkpoint/disks/{role}/{index}");
            let staged = disk_staging.join(index.to_string());
            stage_checkpoint_disk_layer(&source, &staged, index, format)?;

            let next = if format == "qcow2" {
                let (backing, backing_format) = inspect_qcow2(&source)?;
                match backing {
                    Some(backing) => {
                        let backing_source = resolve_backing_path(&source, &backing);
                        if !backing_source.is_file() {
                            return Err(Error::agent(
                                "stage checkpoint disk",
                                format!("missing qcow2 backing image {}", backing_source.display()),
                            ));
                        }
                        let next_format =
                            detect_disk_format(&backing_source, backing_format.as_deref())?;
                        let next_target = disk_target(role, index + 1, next_format)?;
                        rewrite_qcow2_backing(&staged, &next_target)?;
                        Some((backing_source, next_format))
                    }
                    None => None,
                }
            } else {
                None
            };

            let metadata = std::fs::metadata(&staged)
                .map_err(|error| Error::agent("inspect checkpoint disk", error.to_string()))?;
            // The pack footer authenticates the entire compressed asset blob.
            // Avoid hashing a 20 GiB logical raw backing full of sparse holes.
            let asset = CheckpointAsset {
                path: artifact_path,
                size: metadata.len(),
                sha256: String::new(),
            };
            files.push(CheckpointDiskFile {
                asset,
                target,
                format: format.to_string(),
            });
            match next {
                Some((next_source, next_format)) => {
                    source = next_source;
                    format = next_format;
                }
                None => break,
            }
        }
        if files.is_empty() || files.len() == 64 {
            return Err(Error::agent(
                "stage checkpoint disk",
                format!("invalid or unterminated {role} disk chain"),
            ));
        }
        disks.push(CheckpointDisk {
            role: role.to_string(),
            files,
        });
    }
    if disks.len() != 2 {
        return Err(Error::agent(
            "stage checkpoint disk",
            "portable checkpoints require storage and overlay disks",
        ));
    }
    Ok(disks)
}

fn stage_checkpoint_disk_layer(
    source: &Path,
    staged: &Path,
    index: usize,
    format: &str,
) -> Result<()> {
    if index == 0 || format == "qcow2" {
        // The active top is writable, and every qcow2 layer below it has a
        // backing filename that is rewritten for the self-contained artifact.
        // Both therefore need a private inode. Hard-linking a qcow2 backing and
        // editing its header corrupts the live source's disk chain.
        return crate::disk_utils::clone_or_copy_file(source, staged);
    }

    // Terminal raw backings are immutable and carry no header to rewrite. An
    // owned hard link is an exact O(1) snapshot and survives source deletion.
    match std::fs::hard_link(source, staged) {
        Ok(()) => Ok(()),
        Err(error) if error.raw_os_error() == Some(libc::EXDEV) => {
            crate::disk_utils::clone_or_copy_file(source, staged)
        }
        Err(error) => Err(Error::agent("stage checkpoint disk", error.to_string())),
    }
}

/// Build an integrity entry for a staged checkpoint payload.
pub fn describe_asset(path: &Path, relative_path: &str) -> Result<CheckpointAsset> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| Error::agent("inspect checkpoint payload", error.to_string()))?;
    if !metadata.file_type().is_file() {
        return Err(Error::agent(
            "inspect checkpoint payload",
            format!("{} is not a regular file", path.display()),
        ));
    }
    let mut file = std::fs::File::open(path)
        .map_err(|error| Error::agent("open checkpoint payload", error.to_string()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| Error::agent("hash checkpoint payload", error.to_string()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(CheckpointAsset {
        path: relative_path.to_string(),
        size: metadata.len(),
        sha256: hex::encode(hasher.finalize()),
    })
}

fn describe_sparse_asset(path: &Path, relative_path: &str) -> Result<CheckpointAsset> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| Error::agent("inspect checkpoint payload", error.to_string()))?;
    if !metadata.file_type().is_file() {
        return Err(Error::agent(
            "inspect checkpoint payload",
            format!("{} is not a regular file", path.display()),
        ));
    }
    Ok(CheckpointAsset {
        path: relative_path.to_string(),
        size: metadata.len(),
        sha256: String::new(),
    })
}

/// Validate that a checkpoint may be restored by this host and runtime.
pub fn validate_compatibility(checkpoint: &PortableCheckpointManifest) -> Result<()> {
    if checkpoint.version != FORMAT_VERSION {
        return Err(Error::agent(
            "restore checkpoint",
            format!(
                "unsupported checkpoint version {} (runtime requires {})",
                checkpoint.version, FORMAT_VERSION
            ),
        ));
    }
    if checkpoint.runtime_abi != RUNTIME_ABI {
        return Err(Error::agent(
            "restore checkpoint",
            format!(
                "checkpoint requires runtime ABI '{}', this runtime provides '{}'",
                checkpoint.runtime_abi, RUNTIME_ABI
            ),
        ));
    }
    let host_platform = crate::platform::Platform::current()
        .host_oci_platform()
        .to_string();
    if checkpoint.host_platform != host_platform {
        return Err(Error::agent(
            "restore checkpoint",
            format!(
                "checkpoint host platform '{}' does not match '{}'",
                checkpoint.host_platform, host_platform
            ),
        ));
    }
    if checkpoint.device_profile != DEVICE_PROFILE {
        return Err(Error::agent(
            "restore checkpoint",
            format!(
                "unsupported checkpoint device profile '{}'",
                checkpoint.device_profile
            ),
        ));
    }
    if checkpoint.version >= 2 {
        let network = checkpoint.network.as_ref().ok_or_else(|| {
            Error::agent(
                "restore checkpoint",
                "version-two checkpoint is missing its network descriptor",
            )
        })?;
        let backend = restored_network_backend(checkpoint)?;
        let mut hosts = std::collections::HashSet::new();
        for port in &network.ports {
            if port.host == 0 || port.guest == 0 || !hosts.insert(port.host) {
                return Err(Error::agent(
                    "restore checkpoint",
                    "checkpoint contains an invalid or duplicate port mapping",
                ));
            }
        }
        if !network.ports.is_empty() && backend != Some(crate::network::NetworkBackend::VirtioNet) {
            return Err(Error::agent(
                "restore checkpoint",
                "checkpoint port mappings require the virtio-net backend",
            ));
        }
        if !network.enabled && (!network.ports.is_empty() || backend.is_some()) {
            return Err(Error::agent(
                "restore checkpoint",
                "checkpoint network descriptor is internally inconsistent",
            ));
        }
        if let Some(workload) = checkpoint.workload.as_ref() {
            if workload.image.trim().is_empty() {
                return Err(Error::agent(
                    "restore checkpoint",
                    "checkpoint workload image is empty",
                ));
            }
            if crate::data::validate_vm_name(&workload.overlay_owner, "overlay owner").is_err() {
                return Err(Error::agent(
                    "restore checkpoint",
                    "checkpoint workload overlay owner is invalid",
                ));
            }
            if workload
                .restart_policy
                .parse::<crate::config::RestartPolicy>()
                .is_err()
            {
                return Err(Error::agent(
                    "restore checkpoint",
                    "checkpoint workload restart policy is invalid",
                ));
            }
        }
    }
    if checkpoint.cpus == 0 || checkpoint.memory_mib == 0 {
        return Err(Error::agent(
            "restore checkpoint",
            "checkpoint has invalid zero CPU or memory resources",
        ));
    }
    // Reject resource-exhaustion artifacts before extracting or mapping their
    // memory image. The current device profile maps configured RAM plus rootfs
    // DAX and small fixed regions; 2 GiB is a deliberately generous ceiling
    // for those non-configured mappings.
    const MAX_STATE_BYTES: u64 = 64 * 1024 * 1024;
    const MAX_LAYOUT_BYTES: u64 = 1024 * 1024;
    const FIXED_MEMORY_OVERHEAD_BYTES: u64 = 2 * 1024 * 1024 * 1024;
    let configured_memory = u64::from(checkpoint.memory_mib)
        .checked_mul(1024 * 1024)
        .ok_or_else(|| Error::agent("restore checkpoint", "memory size overflow"))?;
    let max_memory_image = configured_memory
        .checked_add(FIXED_MEMORY_OVERHEAD_BYTES)
        .ok_or_else(|| Error::agent("restore checkpoint", "memory size overflow"))?;
    if checkpoint.state.size == 0
        || checkpoint.state.size > MAX_STATE_BYTES
        || checkpoint.layout.size == 0
        || checkpoint.layout.size > MAX_LAYOUT_BYTES
        || checkpoint.memory.size == 0
        || checkpoint.memory.size > max_memory_image
    {
        return Err(Error::agent(
            "restore checkpoint",
            "checkpoint payload sizes are inconsistent with the captured machine",
        ));
    }
    validate_cpu_compatibility(checkpoint)
}

fn expected_assets(
    checkpoint: &PortableCheckpointManifest,
) -> [(&CheckpointAsset, &'static str); 3] {
    [
        (&checkpoint.state, "checkpoint/checkpoint.bin"),
        (&checkpoint.memory, "checkpoint/memory.bin"),
        (&checkpoint.layout, "checkpoint/manifest.bin"),
    ]
}

fn validate_disk_manifest(disks: &[CheckpointDisk]) -> Result<()> {
    if disks.len() != 2 {
        return Err(Error::agent(
            "install checkpoint",
            "checkpoint must contain storage and overlay disk chains",
        ));
    }
    for (expected_role, disk) in ["storage", "overlay"].into_iter().zip(disks) {
        if disk.role != expected_role || disk.files.is_empty() {
            return Err(Error::agent(
                "install checkpoint",
                format!("invalid {} disk chain", disk.role),
            ));
        }
        for (index, file) in disk.files.iter().enumerate() {
            if file.format != "raw" && file.format != "qcow2" {
                return Err(Error::agent(
                    "install checkpoint",
                    format!("unsupported checkpoint disk format '{}'", file.format),
                ));
            }
            let expected_target = disk_target(&disk.role, index, &file.format)?;
            let expected_path = format!("checkpoint/disks/{}/{index}", disk.role);
            if file.target != expected_target || file.asset.path != expected_path {
                return Err(Error::agent(
                    "install checkpoint",
                    format!(
                        "invalid checkpoint disk mapping '{} -> {}'",
                        file.asset.path, file.target
                    ),
                ));
            }
            if file.format == "raw" && index + 1 != disk.files.len() {
                return Err(Error::agent(
                    "install checkpoint",
                    "a raw disk must terminate its image chain",
                ));
            }
        }
    }
    Ok(())
}

fn copy_verified(
    source: &Path,
    destination: &Path,
    asset: &CheckpointAsset,
    writable: bool,
) -> Result<()> {
    let metadata = std::fs::symlink_metadata(source)
        .map_err(|error| Error::agent("inspect checkpoint payload", error.to_string()))?;
    if !metadata.file_type().is_file() || metadata.len() != asset.size {
        return Err(Error::agent(
            "verify checkpoint payload",
            format!("{} has an unexpected type or size", source.display()),
        ));
    }
    if asset.sha256.is_empty() {
        if !writable {
            return Err(Error::agent(
                "verify checkpoint payload",
                format!("{} is missing its SHA-256 digest", source.display()),
            ));
        }
    } else {
        let mut input = std::fs::File::open(source)
            .map_err(|error| Error::agent("open checkpoint payload", error.to_string()))?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0_u8; 1024 * 1024];
        loop {
            let read = input
                .read(&mut buffer)
                .map_err(|error| Error::agent("read checkpoint payload", error.to_string()))?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        if hex::encode(hasher.finalize()) != asset.sha256 {
            return Err(Error::agent(
                "verify checkpoint payload",
                format!("SHA-256 mismatch for {}", source.display()),
            ));
        }
    }

    if writable {
        // Restored guest RAM is mapped writable and becomes backing for future
        // forks. It must never alias the immutable extraction cache. Prefer a
        // filesystem reflink so even a multi-GiB sparse image stays cheap; the
        // fallback preserves holes while copying only allocated extents.
        crate::disk_utils::clone_or_copy_file(source, destination)?;
        std::fs::File::open(destination)
            .and_then(|file| file.sync_all())
            .map_err(|error| Error::agent("sync checkpoint payload", error.to_string()))?;
        return Ok(());
    }

    // VM/device state and the memory-layout manifest stay read-only. Keep an
    // owned hard link when the extraction cache shares this filesystem; cache
    // eviction unlinks only its name.
    match std::fs::hard_link(source, destination) {
        Ok(()) => Ok(()),
        Err(error) if error.raw_os_error() == Some(libc::EXDEV) => {
            let mut input = std::fs::File::open(source)
                .map_err(|error| Error::agent("open checkpoint payload", error.to_string()))?;
            let mut output = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(destination)
                .map_err(|error| Error::agent("create checkpoint payload", error.to_string()))?;
            std::io::copy(&mut input, &mut output)
                .map_err(|error| Error::agent("copy checkpoint payload", error.to_string()))?;
            output
                .sync_all()
                .map_err(|error| Error::agent("sync checkpoint payload", error.to_string()))?;
            Ok(())
        }
        Err(error) => Err(Error::agent("link checkpoint payload", error.to_string())),
    }
}

fn copy_verified_sparse(source: &Path, destination: &Path, asset: &CheckpointAsset) -> Result<()> {
    let metadata = std::fs::symlink_metadata(source)
        .map_err(|error| Error::agent("inspect checkpoint disk", error.to_string()))?;
    if !metadata.file_type().is_file() || metadata.len() != asset.size {
        return Err(Error::agent(
            "verify checkpoint disk",
            format!("size/type mismatch for {}", source.display()),
        ));
    }
    // Disk assets are already covered by the pack's whole-blob SHA-256. A
    // second logical-file hash would read every sparse hole and turn a small
    // qcow2 chain into minutes of CPU work.
    if !asset.sha256.is_empty() {
        return Err(Error::agent(
            "verify checkpoint disk",
            "sparse disk assets must use container-level integrity",
        ));
    }
    crate::disk_utils::clone_or_copy_file(source, destination)?;
    std::fs::File::open(destination)
        .and_then(|file| file.sync_all())
        .map_err(|error| Error::agent("sync checkpoint disk", error.to_string()))?;
    Ok(())
}

/// Publish an immutable backing image without copying its sparse address space.
///
/// Extracted artifacts and VM data normally share a filesystem, so a hard link
/// makes even a multi-gigabyte sparse raw backing an O(1) install. The VM owns a
/// second link after the extraction cache is pruned. Cross-filesystem/private
/// extraction falls back to the ordinary reflink/sparse-copy path.
fn link_or_copy_verified_sparse(
    source: &Path,
    destination: &Path,
    asset: &CheckpointAsset,
) -> Result<()> {
    let metadata = std::fs::symlink_metadata(source)
        .map_err(|error| Error::agent("inspect checkpoint disk", error.to_string()))?;
    if !metadata.file_type().is_file() || metadata.len() != asset.size {
        return Err(Error::agent(
            "verify checkpoint disk",
            format!("size/type mismatch for {}", source.display()),
        ));
    }
    if !asset.sha256.is_empty() {
        return Err(Error::agent(
            "verify checkpoint disk",
            "sparse disk assets must use container-level integrity",
        ));
    }
    match std::fs::hard_link(source, destination) {
        Ok(()) => Ok(()),
        Err(error) if error.raw_os_error() == Some(libc::EXDEV) => {
            copy_verified_sparse(source, destination, asset)
        }
        Err(error) => Err(Error::agent("link checkpoint disk", error.to_string())),
    }
}

/// Install an extracted artifact's checkpoint into one machine's private data
/// directory and mark it for one-shot restore.
pub fn install(
    extracted: &Path,
    vm_data_dir: &Path,
    checkpoint: &PortableCheckpointManifest,
) -> Result<()> {
    validate_compatibility(checkpoint)?;
    validate_disk_manifest(&checkpoint.disks)?;
    let destination = vm_data_dir.join(INSTALLED_DIR);
    if destination.exists() {
        return Err(Error::agent(
            "install checkpoint",
            format!("{} already exists", destination.display()),
        ));
    }
    let partial = vm_data_dir.join(format!(".{INSTALLED_DIR}-{}-partial", std::process::id()));
    let _ = std::fs::remove_dir_all(&partial);
    std::fs::create_dir(&partial)
        .map_err(|error| Error::agent("create checkpoint directory", error.to_string()))?;

    let result = (|| -> Result<()> {
        for (asset, expected) in expected_assets(checkpoint) {
            if asset.path != expected {
                return Err(Error::agent(
                    "install checkpoint",
                    format!("unexpected checkpoint asset path '{}'", asset.path),
                ));
            }
            let filename = Path::new(expected)
                .file_name()
                .expect("fixed checkpoint asset path");
            copy_verified(
                &extracted.join(expected),
                &partial.join(filename),
                asset,
                expected == "checkpoint/memory.bin",
            )?;
        }

        let staged_disks = partial.join("disks");
        std::fs::create_dir(&staged_disks)
            .map_err(|error| Error::agent("stage checkpoint disks", error.to_string()))?;
        for disk in &checkpoint.disks {
            for (index, file) in disk.files.iter().enumerate() {
                let staged = staged_disks.join(&file.target);
                let source = extracted.join(&file.asset.path);
                if index == 0 {
                    // The active top layer is writable after resume and must
                    // never alias the immutable extraction cache.
                    copy_verified_sparse(&source, &staged, &file.asset)?;
                } else {
                    // Backings remain immutable. Linking them avoids scanning
                    // tens of GiB of sparse holes during every import.
                    link_or_copy_verified_sparse(&source, &staged, &file.asset)?;
                }
                if file.format == "qcow2" {
                    let (backing, _) = inspect_qcow2(&staged)?;
                    let expected_backing =
                        disk.files.get(index + 1).map(|next| next.target.as_str());
                    if backing.as_deref() != expected_backing {
                        return Err(Error::agent(
                            "install checkpoint",
                            format!(
                                "qcow2 '{}' references {:?}, expected {:?}",
                                file.target, backing, expected_backing
                            ),
                        ));
                    }
                }
            }
        }
        std::fs::write(partial.join(PENDING_MARKER), b"1\n")
            .map_err(|error| Error::agent("mark checkpoint pending", error.to_string()))?;
        std::fs::rename(&partial, &destination)
            .map_err(|error| Error::agent("publish checkpoint", error.to_string()))?;

        // Publish the exact captured block chains into the paths the launcher
        // attaches. Creation is still private/uncommitted at this point, so a
        // failure causes the entire machine reservation to be rolled back.
        for raw_name in [
            crate::storage::STORAGE_DISK_FILENAME,
            crate::storage::OVERLAY_DISK_FILENAME,
        ] {
            for path in [
                vm_data_dir.join(raw_name),
                vm_data_dir.join(Path::new(raw_name).with_extension("qcow2")),
            ] {
                if path.exists() {
                    std::fs::remove_file(&path).map_err(|error| {
                        Error::agent("replace checkpoint disk", error.to_string())
                    })?;
                }
            }
        }
        for disk in &checkpoint.disks {
            for file in &disk.files {
                // The staged chain is already private (top) or has an owned
                // hard link (immutable backing). Move those exact inodes into
                // the launcher's disk namespace instead of copying them again.
                std::fs::rename(
                    destination.join("disks").join(&file.target),
                    vm_data_dir.join(&file.target),
                )
                .map_err(|error| Error::agent("publish checkpoint disk", error.to_string()))?;
            }
            std::fs::write(vm_data_dir.join(format!("{}.formatted", disk.role)), b"1").map_err(
                |error| Error::agent("mark checkpoint disk formatted", error.to_string()),
            )?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_dir_all(&partial);
        let _ = std::fs::remove_dir_all(&destination);
    }
    result
}

/// Remove the extracted pack used only to transport a portable checkpoint.
///
/// All checkpoint state and disk chains have their own links or private copies
/// in the machine data directory after [`install`] succeeds. Leaving the pack
/// marker behind is not harmless: the generic restart path interprets any
/// extracted pack as OCI layers and attaches an extra virtio-fs device. That
/// changes the captured device/IRQ topology and makes the restored guest unable
/// to receive its vsock interrupt.
pub fn discard_transport_pack(vm_data_dir: &Path) -> Result<()> {
    let pack_dir = vm_data_dir.join("pack");
    smolvm_pack::extract::force_detach_layers_volume(&pack_dir);
    match std::fs::remove_dir_all(&pack_dir) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Error::agent(
            "discard checkpoint transport pack",
            error.to_string(),
        )),
    }
}

/// Finish a portable live restore before exposing the machine to callers.
///
/// The restored guest still contains the source machine's live container and
/// per-machine identity. Rejuvenation re-mints that identity and records the
/// inherited crun container ID so later `machine exec` calls join the restored
/// workload instead of silently creating a second container.
pub fn finalize_live_restore(name: &str, record: &VmRecord) -> Result<()> {
    crate::agent::fork::rejuvenate_clone(name, record)?;
    crate::agent::fork::release_forkpoint(name)
}

/// Return the pending one-shot checkpoint directory for a machine, if any.
pub fn pending_dir(vm_data_dir: &Path) -> Option<PathBuf> {
    let dir = vm_data_dir.join(INSTALLED_DIR);
    let marker = dir.join(PENDING_MARKER);
    if marker.is_file()
        && dir.join("checkpoint.bin").is_file()
        && dir.join("memory.bin").is_file()
        && dir.join("manifest.bin").is_file()
    {
        Some(dir)
    } else {
        None
    }
}

/// Consume a successfully restored checkpoint so later starts cold-boot from
/// the machine's current disks rather than replaying stale live state.
pub fn consume(vm_data_dir: &Path) -> Result<()> {
    consume_with_retained_backing(vm_data_dir, cfg!(target_os = "macos"))
}

fn consume_with_retained_backing(vm_data_dir: &Path, retain_memory: bool) -> Result<()> {
    let Some(dir) = pending_dir(vm_data_dir) else {
        return Ok(());
    };
    let mut retained_memory = None;
    if retain_memory {
        let source = dir.join("memory.bin");
        let destination = vm_data_dir.join(RETAINED_MEMORY_BACKING);
        if destination.exists() {
            return Err(Error::agent(
                "consume checkpoint",
                format!(
                    "retained memory backing already exists: {}",
                    destination.display()
                ),
            ));
        }
        std::fs::rename(&source, &destination)
            .map_err(|error| Error::agent("retain checkpoint memory", error.to_string()))?;
        retained_memory = Some((source, destination));
    }
    std::fs::remove_file(dir.join(PENDING_MARKER)).map_err(|error| {
        if let Some((source, destination)) = retained_memory.as_ref() {
            if let Err(rollback_error) = std::fs::rename(destination, source) {
                tracing::warn!(
                    source = %source.display(),
                    destination = %destination.display(),
                    %rollback_error,
                    "failed to roll back retained checkpoint memory"
                );
            }
        }
        Error::agent("consume checkpoint", error.to_string())
    })?;
    if let Err(error) = std::fs::remove_dir_all(&dir) {
        tracing::warn!(path = %dir.display(), %error, "checkpoint consumed but payload cleanup failed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_verifies_and_consumes_checkpoint() {
        let extracted = tempfile::tempdir().unwrap();
        let source = extracted.path().join(ASSET_DIR);
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("checkpoint.bin"), b"state").unwrap();
        std::fs::write(source.join("memory.bin"), b"memory").unwrap();
        std::fs::write(source.join("manifest.bin"), b"layout").unwrap();
        for role in ["storage", "overlay"] {
            let disk_dir = source.join("disks").join(role);
            std::fs::create_dir_all(&disk_dir).unwrap();
            std::fs::write(disk_dir.join("0"), format!("{role}-disk")).unwrap();
        }
        let disk = |role: &str, target: &str| CheckpointDisk {
            role: role.to_string(),
            files: vec![CheckpointDiskFile {
                asset: CheckpointAsset {
                    path: format!("checkpoint/disks/{role}/0"),
                    size: std::fs::metadata(source.join("disks").join(role).join("0"))
                        .unwrap()
                        .len(),
                    sha256: String::new(),
                },
                target: target.to_string(),
                format: "raw".to_string(),
            }],
        };
        let metadata = PortableCheckpointManifest {
            version: FORMAT_VERSION,
            runtime_abi: RUNTIME_ABI.to_string(),
            host_platform: crate::platform::Platform::current()
                .host_oci_platform()
                .to_string(),
            cpu_contract: checkpoint_cpu_contract().unwrap(),
            cpus: 2,
            memory_mib: 512,
            storage_gib: None,
            overlay_gib: None,
            device_profile: DEVICE_PROFILE.to_string(),
            state: describe_asset(&source.join("checkpoint.bin"), "checkpoint/checkpoint.bin")
                .unwrap(),
            memory: describe_sparse_asset(&source.join("memory.bin"), "checkpoint/memory.bin")
                .unwrap(),
            layout: describe_asset(&source.join("manifest.bin"), "checkpoint/manifest.bin")
                .unwrap(),
            disks: vec![
                disk("storage", "storage.raw"),
                disk("overlay", "overlay.raw"),
            ],
            workload: None,
            network: Some(CheckpointNetwork::default()),
        };
        let machine = tempfile::tempdir().unwrap();
        install(extracted.path(), machine.path(), &metadata).unwrap();
        assert!(metadata.memory.sha256.is_empty());
        assert!(pending_dir(machine.path()).is_some());
        assert_eq!(
            std::fs::read(machine.path().join("storage.raw")).unwrap(),
            b"storage-disk"
        );
        assert_eq!(
            std::fs::read(machine.path().join("overlay.raw")).unwrap(),
            b"overlay-disk"
        );
        assert!(machine.path().join("storage.formatted").is_file());
        assert!(machine.path().join("overlay.formatted").is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_ne!(
                std::fs::metadata(source.join("memory.bin")).unwrap().ino(),
                std::fs::metadata(machine.path().join(INSTALLED_DIR).join("memory.bin"))
                    .unwrap()
                    .ino()
            );
        }
        std::fs::write(
            machine.path().join(INSTALLED_DIR).join("memory.bin"),
            b"private",
        )
        .unwrap();
        assert_eq!(std::fs::read(source.join("memory.bin")).unwrap(), b"memory");
        consume(machine.path()).unwrap();
        assert!(pending_dir(machine.path()).is_none());
        assert_eq!(
            machine.path().join(RETAINED_MEMORY_BACKING).exists(),
            cfg!(target_os = "macos")
        );
        assert_eq!(
            std::fs::read(machine.path().join("storage.raw")).unwrap(),
            b"storage-disk"
        );

        let mut oversized = metadata.clone();
        oversized.memory.size =
            u64::from(oversized.memory_mib) * 1024 * 1024 + 2 * 1024 * 1024 * 1024 + 1;
        assert!(validate_compatibility(&oversized).is_err());

        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            validate_compatibility(&metadata).expect("capturing host satisfies its CPU contract");
            match cpu_vendor().unwrap().as_deref() {
                Some("GenuineIntel") => assert_eq!(
                    metadata.cpu_contract,
                    CheckpointCpuContract::LinuxKvmIntelPortableV1
                ),
                _ => assert_eq!(
                    metadata.cpu_contract,
                    CheckpointCpuContract::ExactV1 {
                        fingerprint: cpu_fingerprint().unwrap(),
                    }
                ),
            }
        }

        let mut exact_mismatch = metadata.clone();
        exact_mismatch.cpu_contract = CheckpointCpuContract::ExactV1 {
            fingerprint: "different-host".to_string(),
        };
        assert!(validate_compatibility(&exact_mismatch).is_err());

        let mut incompatible = metadata;
        incompatible.runtime_abi.push_str("-other");
        assert!(validate_compatibility(&incompatible).is_err());
    }

    #[test]
    fn immutable_checkpoint_payload_requires_digest() {
        let source = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(source.path(), b"state").unwrap();
        let destination_dir = tempfile::tempdir().unwrap();
        let destination = destination_dir.path().join("state-copy");
        let asset = CheckpointAsset {
            path: "checkpoint/checkpoint.bin".to_string(),
            size: 5,
            sha256: String::new(),
        };

        let error = copy_verified(source.path(), &destination, &asset, false)
            .unwrap_err()
            .to_string();
        assert!(error.contains("missing its SHA-256 digest"), "{error}");
    }

    #[test]
    fn checkpoint_transport_pack_is_removed_after_install() {
        let machine = tempfile::tempdir().unwrap();
        let pack = machine.path().join("pack");
        std::fs::create_dir(&pack).unwrap();
        std::fs::write(pack.join(".smolvm-extracted"), b"").unwrap();
        std::fs::write(pack.join("transport-only"), b"payload").unwrap();

        discard_transport_pack(machine.path()).unwrap();

        assert!(!pack.exists());
    }

    #[cfg(unix)]
    #[test]
    fn qcow2_backing_staging_never_aliases_the_live_header() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let qcow_staged = dir.path().join("qcow-staged");
        let raw_staged = dir.path().join("raw-staged");
        std::fs::write(&source, b"disk-layer").unwrap();

        stage_checkpoint_disk_layer(&source, &qcow_staged, 1, "qcow2").unwrap();
        assert_ne!(
            std::fs::metadata(&source).unwrap().ino(),
            std::fs::metadata(&qcow_staged).unwrap().ino()
        );

        stage_checkpoint_disk_layer(&source, &raw_staged, 1, "raw").unwrap();
        assert_eq!(
            std::fs::metadata(&source).unwrap().ino(),
            std::fs::metadata(&raw_staged).unwrap().ino()
        );
    }

    #[test]
    fn checkpoint_backings_do_not_collide_with_runtime_directories() {
        for role in ["storage", "overlay"] {
            for index in 1..64 {
                let target = disk_target(role, index, "qcow2").unwrap();
                assert_ne!(target, "d");
                assert_ne!(target, "s");
                assert!(target.starts_with(".smolcheckpoint-"));
            }
        }
    }

    #[test]
    fn consume_can_retain_a_live_memory_backing() {
        let machine = tempfile::tempdir().unwrap();
        let pending = machine.path().join(INSTALLED_DIR);
        std::fs::create_dir(&pending).unwrap();
        std::fs::write(pending.join(PENDING_MARKER), b"1\n").unwrap();
        std::fs::write(pending.join("checkpoint.bin"), b"state").unwrap();
        std::fs::write(pending.join("manifest.bin"), b"layout").unwrap();
        std::fs::write(pending.join("memory.bin"), b"live-memory").unwrap();

        consume_with_retained_backing(machine.path(), true).unwrap();

        assert!(pending_dir(machine.path()).is_none());
        assert!(!pending.exists());
        assert_eq!(
            std::fs::read(machine.path().join(RETAINED_MEMORY_BACKING)).unwrap(),
            b"live-memory"
        );
    }

    #[test]
    fn common_image_service_is_checkpoint_eligible() {
        let mut record = VmRecord::new(
            "image-service".to_string(),
            2,
            1024,
            Vec::new(),
            vec![(18080, 8080)],
            true,
        );
        record.image = Some("python:3.12-alpine".to_string());
        record.network_backend = Some(crate::network::NetworkBackend::VirtioNet);
        record.restart.policy = crate::config::RestartPolicy::OnFailure;
        record.restart.max_retries = 7;
        record.restart.max_backoff_secs = 19;

        validate_capture_profile(&record).expect("image + network + ports must be portable");
        let workload = checkpoint_workload(&record.name, &record).unwrap();
        assert_eq!(workload.image, "python:3.12-alpine");
        assert_eq!(workload.overlay_owner, "image-service");
        assert_eq!(workload.restart_policy, "on-failure");
        assert_eq!(workload.restart_max_retries, 7);
        assert_eq!(workload.restart_max_backoff_secs, 19);
        let network = checkpoint_network(&record);
        assert!(network.enabled);
        assert_eq!(network.backend.as_deref(), Some("virtio-net"));
        assert_eq!(
            network.ports,
            vec![CheckpointPort {
                host: 18080,
                guest: 8080
            }]
        );
    }

    #[test]
    fn host_bound_attachments_remain_ineligible() {
        let mut record = VmRecord::new(
            "host-bound".to_string(),
            2,
            1024,
            vec![("/host".to_string(), "/guest".to_string(), true)],
            Vec::new(),
            false,
        );
        record.image = Some("alpine:3.20".to_string());
        let error = validate_capture_profile(&record).unwrap_err().to_string();
        assert!(error.contains("host mounts"), "{error}");

        record.mounts.clear();
        record.source_smolmachine = Some("/tmp/source.smolmachine".to_string());
        let error = validate_capture_profile(&record).unwrap_err().to_string();
        assert!(error.contains("host-backed image layers"), "{error}");
    }

    #[test]
    fn unreleased_checkpoint_versions_are_rejected() {
        let mut metadata = PortableCheckpointManifest {
            version: FORMAT_VERSION,
            runtime_abi: RUNTIME_ABI.to_string(),
            host_platform: crate::platform::Platform::current()
                .host_oci_platform()
                .to_string(),
            cpu_contract: checkpoint_cpu_contract().unwrap(),
            cpus: 1,
            memory_mib: 1,
            storage_gib: None,
            overlay_gib: None,
            device_profile: DEVICE_PROFILE.to_string(),
            state: CheckpointAsset {
                path: "checkpoint/checkpoint.bin".to_string(),
                size: 1,
                sha256: "00".repeat(32),
            },
            memory: CheckpointAsset {
                path: "checkpoint/memory.bin".to_string(),
                size: 1,
                sha256: "00".repeat(32),
            },
            layout: CheckpointAsset {
                path: "checkpoint/manifest.bin".to_string(),
                size: 1,
                sha256: "00".repeat(32),
            },
            disks: Vec::new(),
            workload: None,
            network: Some(CheckpointNetwork::default()),
        };
        validate_compatibility(&metadata).unwrap();
        metadata.version = FORMAT_VERSION - 1;
        assert!(validate_compatibility(&metadata).is_err());
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn linux_cpu_vendor_parser_is_bounded_and_first_processor_only() {
        assert_eq!(
            linux_cpu_vendor(
                "processor: 0\nvendor_id: GenuineIntel\n\nprocessor: 1\nvendor_id: Other\n"
            ),
            Some("GenuineIntel".to_string())
        );
        assert_eq!(linux_cpu_vendor("processor: 0\nmodel: 1\n\n"), None);
        let oversized = "x".repeat(65);
        assert_eq!(
            linux_cpu_vendor(&format!("vendor_id: {oversized}\n\n")),
            None
        );
    }
}

#[cfg(test)]
mod aarch64_feature_contract_tests {
    //! Fixtures are real `sysctl -a` output shapes from an M1 Pro
    //! (MacBookPro18,3) and an M4 Max (Mac16,6), captured 2026-08-30.
    use super::missing_features;

    fn v(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    /// The twenty features an M4 Max has that an M1 Pro does not, minus SME
    /// (masked from every guest), leaves these ten.
    const M4_ONLY: &[&str] = &[
        "FEAT_AFP",
        "FEAT_BF16",
        "FEAT_BTI",
        "FEAT_ECV",
        "FEAT_FPAC",
        "FEAT_FPACCOMBINE",
        "FEAT_I8MM",
        "FEAT_PAuth2",
        "FEAT_RPRES",
        "FEAT_WFxT",
    ];
    /// The one feature an M1 Pro has that an M4 Max does not.
    const M1_ONLY: &[&str] = &["FEAT_SSBS"];
    const SHARED: &[&str] = &["FEAT_LSE", "FEAT_FP16", "FEAT_DotProd", "FEAT_PAuth"];

    fn m4() -> Vec<String> {
        let mut f = v(SHARED);
        f.extend(v(M4_ONLY));
        f
    }
    fn m1() -> Vec<String> {
        let mut f = v(SHARED);
        f.extend(v(M1_ONLY));
        f
    }

    #[test]
    fn a_host_with_the_same_features_accepts_the_checkpoint() {
        assert!(missing_features(&m4(), &m4()).is_empty());
    }

    /// Extra features on the destination are harmless: the guest already decided
    /// at boot what it would use.
    #[test]
    fn a_richer_host_accepts_a_leaner_checkpoint() {
        let lean = v(SHARED);
        assert!(missing_features(&lean, &m4()).is_empty());
    }

    /// The case the whole contract exists for: a guest that probed an M4 cannot
    /// resume where those instructions do not exist.
    #[test]
    fn an_m4_checkpoint_is_refused_on_an_m1() {
        let missing = missing_features(&m4(), &m1());
        assert_eq!(
            missing,
            v(M4_ONLY),
            "every M4-only feature must be reported"
        );
        assert!(missing.contains(&"FEAT_BF16".to_string()));
        assert!(missing.contains(&"FEAT_I8MM".to_string()));
    }

    /// Newer is NOT automatically a superset, so "older to newer is safe" is
    /// wrong as a rule. The M4 Max lacks FEAT_SSBS, which the M1 Pro has — these
    /// two are unordered and both directions must be refused.
    #[test]
    fn newer_silicon_is_not_automatically_a_superset() {
        let missing = missing_features(&m1(), &m4());
        assert_eq!(
            missing,
            v(M1_ONLY),
            "an M1 checkpoint must be refused on an M4 over FEAT_SSBS"
        );
    }

    /// SME must never reach the contract: libkrun masks it out of every guest,
    /// so recording it would refuse checkpoints over a feature no guest can use.
    #[test]
    fn sme_is_excluded_from_the_contract() {
        use super::is_masked_from_guest;
        for name in [
            "FEAT_SME",
            "FEAT_SME2",
            "FEAT_SME_F64F64",
            "SME_I8I32",
            "SME_B16F32",
        ] {
            assert!(is_masked_from_guest(name), "{name} must be masked");
        }
        for name in ["FEAT_BF16", "FEAT_I8MM", "FEAT_SSBS", "FEAT_LSE"] {
            assert!(!is_masked_from_guest(name), "{name} must be kept");
        }
    }

    #[test]
    fn macos_sysctl_output_is_parsed() {
        use super::parse_macos_features;
        let out = "hw.optional.arm.FEAT_BF16: 1\n\
                   hw.optional.arm.FEAT_SSBS: 0\n\
                   hw.optional.arm.FEAT_I8MM: 1\n\
                   hw.optional.floatingpoint: 1\n\
                   hw.memsize: 38654705664\n";
        let got = parse_macos_features(out);
        assert_eq!(got, vec!["FEAT_BF16".to_string(), "FEAT_I8MM".to_string()]);
    }

    #[test]
    fn linux_cpuinfo_features_are_normalised() {
        use super::parse_linux_features;
        let cpuinfo = "processor\t: 0\n\
                       Features\t: fp asimd bf16 i8mm\n\
                       CPU part\t: 0xd4f\n\
                       \n\
                       processor\t: 1\n\
                       Features\t: fp\n";
        let got = parse_linux_features(cpuinfo);
        assert_eq!(
            got,
            vec![
                "FEAT_FP".to_string(),
                "FEAT_ASIMD".to_string(),
                "FEAT_BF16".to_string(),
                "FEAT_I8MM".to_string()
            ],
            "only the first processor block, upper-cased"
        );
    }
}

#[cfg(test)]
mod aarch64_live_host_tests {
    /// Enumerates THIS machine. Proves the contract is built from real hardware
    /// rather than only from fixtures, and that SME never reaches it.
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn this_host_reports_a_usable_feature_set() {
        let features = super::aarch64_guest_features().expect("enumerate host features");
        assert!(
            features.len() > 10,
            "expected a real feature set, got {features:?}"
        );
        assert!(
            !features.iter().any(|f| f.contains("SME")),
            "SME is masked from guests and must not be in the contract: {features:?}"
        );
        let mut sorted = features.clone();
        sorted.sort();
        assert_eq!(sorted, features, "contract must be sorted for stability");
        eprintln!("host provides {} guest-visible features", features.len());
    }
}
