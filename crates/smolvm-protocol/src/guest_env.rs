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
/// Guest IPv6 (ULA) address. Optional: absent means IPv4-only guest config.
pub const GUEST_IP6: &str = "SMOLVM_NETWORK_GUEST_IP6";
/// Guest-visible default gateway IPv6 address.
pub const GATEWAY6: &str = "SMOLVM_NETWORK_GATEWAY6";
/// Guest IPv6 prefix length.
pub const PREFIX_LEN6: &str = "SMOLVM_NETWORK_PREFIX_LEN6";
/// Guest-visible DNS server IPv4 address.
pub const DNS: &str = "SMOLVM_NETWORK_DNS";
/// Enables the guest-side DNS filtering proxy.
pub const DNS_FILTER: &str = "SMOLVM_DNS_FILTER";
/// Enables the guest-side Docker socket bridge: the agent listens on the
/// `ports::DOCKER` vsock port and proxies each connection to the in-guest
/// Docker daemon socket, so the host can reach it over a Unix socket.
pub const DOCKER_SOCKET: &str = "SMOLVM_DOCKER_SOCKET";

/// Carries the user's published Unix-socket bridges to the guest agent, encoded
/// by [`crate::publish_socket::encode`] (`port|dir|guest_path;…`). The agent
/// decodes it on startup and spawns one relay per entry. Absent means none.
pub const PUBLISH_SOCKETS: &str = "SMOLVM_PUBLISH_SOCKETS";

/// Enables the guest-side raw X11 socket bridge: the agent creates a local X11
/// display socket in the guest and relays each connection out to the host X
/// server over the `ports::X11` vsock port, so guest X clients render on the
/// host X server. The agent also exports `DISPLAY` for the workload.
///
/// This is a boolean sentinel — the value is [`VALUE_ON`] when set.
pub const X11: &str = "SMOLVM_X11";

/// Enables the guest-side waypipe Wayland forwarding daemon: the agent runs
/// `waypipe server` in daemon mode, which creates a Wayland display socket in
/// the guest and forwards every client that connects to it out over the
/// `ports::WAYPIPE` vsock port to the host `waypipe client`. The agent also
/// exports `WAYLAND_DISPLAY` (and `XDG_RUNTIME_DIR`) for the workload.
///
/// Unlike X11, waypipe is a guest binary dependency usually installed after
/// boot, so the daemon starts lazily on the first launch once `waypipe` is on
/// PATH.
///
/// This is a boolean sentinel — the value is [`VALUE_ON`] when set.
pub const WAYPIPE: &str = "SMOLVM_WAYPIPE";

/// Selects which `waypipe` binary the guest daemon runs. When set to a
/// non-empty absolute path, the daemon execs that binary (the host binary the
/// launcher shared into the guest via `WAYPIPE_TAG`, bind-mounted into the
/// container). When unset or empty, the daemon uses `waypipe` from the
/// container's `PATH` (the image's own install).
pub const WAYPIPE_BIN: &str = "SMOLVM_WAYPIPE_BIN";
