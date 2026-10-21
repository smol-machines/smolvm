//! Shared environment-variable contract between the host launcher and guest agent.
//!
//! These names form the protocol boundary between:
//! - the host-side launcher, which decides what features to enable
//! - the guest agent, which reads these vars on startup and acts accordingly
//!
//! They should be treated as stable protocol constants rather than ad hoc
//! launcher strings.

/// Standard "enabled" value for boolean `SMOLVM_*` sentinel env vars.
///
/// The host writes this when a feature is enabled; the guest agent
/// compares against it. A single canonical value prevents `true` / `yes` /
/// `1` mismatches between the two sides.
pub const VALUE_ON: &str = "1";

/// Env var the host sets on guest init to signal GPU acceleration was requested.
///
/// Present means "host asked for GPU"; the guest agent reads this and emits a
/// post-boot sanity log confirming whether `/dev/dri/*` nodes actually appeared.
/// Absent means no GPU was requested.
///
/// This is a boolean sentinel — the value is [`VALUE_ON`] when set.
pub const GPU: &str = "SMOLVM_GPU";

/// Env var the host sets on guest init when CUDA-over-vsock is available.
///
/// The guest agent uses it to stage the bundled CUDA shims into workload
/// containers and the runtime shim uses it to enable guest-RAM zero-copy.
pub const CUDA_ZEROCOPY: &str = "SMOLVM_CUDA_ZEROCOPY";

/// The VM was started as a live-fork golden.
///
/// The guest agent uses this to expose the workload-facing forkpoint helper.
/// Fork clones inherit the already-running helper from the golden snapshot.
pub const FORKABLE: &str = "SMOLVM_FORKABLE";

/// Planned CUDA fork-pool size passed to the guest agent.
///
/// The agent uses this to select fork-friendly workload defaults only when a
/// pool was explicitly declared; ordinary CUDA machines are unaffected.
pub const CUDA_FORK_POOL_SIZE: &str = "SMOLVM_CUDA_FORK_POOL_SIZE";

/// Workload override for automatic PyTorch expandable segments.
///
/// A declared CUDA fork pool enables the policy by default. Setting this to
/// `0`, `false`, `off`, or `no` in the workload environment disables it.
pub const CUDA_EXPANDABLE_SEGMENTS: &str = "SMOLVM_CUDA_EXPANDABLE_SEGMENTS";

/// Env var the host sets on guest init to signal Rosetta 2 x86_64 translation
/// was requested (and is available on the host).
///
/// Present means the host has attached the RosettaLinux runtime as the virtiofs
/// tag [`crate::ROSETTA_TAG`]; the guest agent reads this on startup and, if set,
/// mounts that runtime at [`crate::ROSETTA_GUEST_PATH`] and registers the ptrace
/// wrapper with `binfmt_misc` as the interpreter for x86_64 ELF binaries. Absent
/// means no Rosetta was requested.
///
/// This is a boolean sentinel — the value is [`VALUE_ON`] when set.
pub const ROSETTA: &str = "SMOLVM_ROSETTA";

/// Filename of this VM's readiness marker, written by the agent into the virtiofs
/// rootfs when boot completes. Per VM (so concurrent boots don't race on one
/// shared file); the host pre-creates and polls the same name. Unset → the agent
/// falls back to the shared [`crate::AGENT_READY_MARKER`] constant.
pub const READY_MARKER: &str = "SMOLVM_READY_MARKER";

/// Host wall-clock at VM launch, nanoseconds since the Unix epoch. The agent
/// uses this to set the guest clock when the hypervisor gives the guest no
/// readable paravirt clock (e.g. WHP on Windows, where the guest otherwise
/// boots at ~1999 and every TLS cert validation fails). The agent only applies
/// it when the guest clock already looks obviously wrong, so it never fights an
/// accurate kvmclock (Linux/KVM) or HVF-seeded RTC (macOS).
pub const HOST_TIME_NS: &str = "SMOLVM_HOST_TIME_NS";

/// The machine's name, so the guest can use it where identity matters
/// (the container hostname). Absent for machines whose name is unknown.
pub const MACHINE_NAME: &str = "SMOLVM_MACHINE_NAME";

/// Tunes the in-guest periodic `fstrim` that reclaims freed disk blocks back
/// to the host sparse file: `off`/`0` disables it, `<minutes>` sets the
/// interval. Read by the guest agent; forwarded from the host env verbatim.
pub const DISK_TRIM: &str = "SMOLVM_DISK_TRIM";

/// Selects whether the guest should configure a real virtio NIC.
pub const BACKEND: &str = "SMOLVM_NETWORK_BACKEND";
/// Canonical backend value meaning "configure guest virtio-net".
pub const BACKEND_VIRTIO_NET: &str = "virtio-net";
/// Guest IPv4 address.
pub const GUEST_IP: &str = "SMOLVM_NETWORK_GUEST_IP";
/// Guest-visible default gateway IPv4 address.
pub const GATEWAY: &str = "SMOLVM_NETWORK_GATEWAY";
/// Guest subnet prefix length.
pub const PREFIX_LEN: &str = "SMOLVM_NETWORK_PREFIX_LEN";
/// Guest MAC address in colon-separated string form.
pub const GUEST_MAC: &str = "SMOLVM_NETWORK_GUEST_MAC";
/// Gateway MAC address in colon-separated string form. Optional: set when the
/// CNI pre-programs the gateway as a static neighbor entry
/// so nothing answers ARP on the link, and the guest must install the entry
/// itself rather than resolve it.
pub const GATEWAY_MAC: &str = "SMOLVM_NETWORK_GATEWAY_MAC";
/// Guest IPv6 (ULA) address. Optional: absent means IPv4-only guest config.
pub const GUEST_IP6: &str = "SMOLVM_NETWORK_GUEST_IP6";
/// Guest-visible default gateway IPv6 address.
pub const GATEWAY6: &str = "SMOLVM_NETWORK_GATEWAY6";
/// Guest IPv6 prefix length.
pub const PREFIX_LEN6: &str = "SMOLVM_NETWORK_PREFIX_LEN6";
/// Guest-visible DNS server IPv4 address.
pub const DNS: &str = "SMOLVM_NETWORK_DNS";
/// Resolver `options` for the guest's `/etc/resolv.conf`, space-separated
/// (`--dns-option`, repeatable), e.g. `timeout:1 attempts:3 rotate use-vc`.
/// Every writer of resolv.conf appends them as one `options` line.
pub const DNS_OPTIONS: &str = "SMOLVM_NETWORK_DNS_OPTIONS";
/// Enables the guest clipboard commands that bridge to the host clipboard
/// (set unless the machine was created with `--no-clipboard`).
pub const CLIPBOARD: &str = "SMOLVM_CLIPBOARD";
/// `/dev/shm` size for the workload container (`--shm-size`), already a
/// tmpfs `size=` value from [`shm_size_option`]. Unset = half the guest RAM.
pub const SHM_SIZE: &str = "SMOLVM_SHM_SIZE";

/// Validate a `--shm-size` value and return it as a tmpfs `size=` value: a
/// byte count with an optional `k`, `m` or `g` suffix (`512m`, `2g`), or a
/// share of guest RAM from 1% to 100% (`25%`). The host and the agent both
/// check it, so a hand-edited record cannot reach the mount.
pub fn shm_size_option(value: &str) -> Result<String, String> {
    let value = value.trim().to_ascii_lowercase();
    let refuse = || {
        format!("invalid --shm-size `{value}`: use bytes with an optional k/m/g suffix (e.g. 512m, 2g) or a share of RAM (e.g. 25%)")
    };
    if let Some(percent) = value.strip_suffix('%') {
        return match percent.parse::<u8>() {
            Ok(1..=100) => Ok(value),
            _ => Err(refuse()),
        };
    }
    let digits = value.trim_end_matches(['k', 'm', 'g']);
    if value.len() - digits.len() > 1 {
        return Err(refuse());
    }
    match digits.parse::<u64>() {
        Ok(1..) => Ok(value),
        _ => Err(refuse()),
    }
}
/// Enables the guest-side Docker socket bridge: the agent listens on the
/// `ports::DOCKER` vsock port and proxies each connection to the in-guest
/// Docker daemon socket, so the host can reach it over a Unix socket.
pub const DOCKER_SOCKET: &str = "SMOLVM_DOCKER_SOCKET";

/// Carries the user's published Unix-socket bridges to the guest agent, encoded
/// by [`crate::publish_socket::encode`] (`port|dir|guest_path;…`). The agent
/// decodes it on startup and spawns one relay per entry. Absent means none.
pub const PUBLISH_SOCKETS: &str = "SMOLVM_PUBLISH_SOCKETS";

/// The cache disk to mount, `<guest device>:<guest path>` (for example
/// `/dev/vdc:/cache`): the machine's own copy-on-write layer over a shared
/// base. The agent mounts its ext4 filesystem, making one on a blank base,
/// and exposes it to every workload at the guest path.
pub const CACHE_DISK: &str = "SMOLVM_CACHE_DISK";

/// Guest paths backed by the machine's storage disk, encoded by
/// [`crate::disk_volume::encode`]. The agent binds a per-path directory on the
/// disk at each one in every workload. Absent means none.
pub const DISK_VOLUMES: &str = "SMOLVM_DISK_VOLUMES";

/// Enables forwarding a detached workload's stdout and stderr to the host over
/// the `ports::WORKLOAD_LOGS` vsock port, where the host appends them to the
/// machine's `workload.log`. Absent means the output is discarded.
pub const WORKLOAD_LOGS: &str = "SMOLVM_WORKLOAD_LOGS";

#[cfg(test)]
mod shm_size_tests {
    use super::shm_size_option;

    #[test]
    fn shm_size_takes_byte_counts_and_shares_of_ram() {
        for (given, size) in [
            ("512m", "512m"),
            ("2G", "2g"),
            ("65536k", "65536k"),
            ("1048576", "1048576"),
            ("25%", "25%"),
            ("100%", "100%"),
        ] {
            assert_eq!(shm_size_option(given).as_deref(), Ok(size), "{given}");
        }
        for bad in [
            "", "0", "0m", "0%", "101%", "1.5g", "2gb", "-1m", "m", "10t", "50%%", "size=1g",
        ] {
            assert!(shm_size_option(bad).is_err(), "{bad:?} must be refused");
        }
    }
}
