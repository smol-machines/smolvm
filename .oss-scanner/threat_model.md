# Threat model: smolvm

This file is read by Anthropic's OSS Scanner before it audits the repository. It restates
`SECURITY.md` and `docs/security-model.md` in the form the scanner asks for; those two files
are authoritative where they differ.

## What this project does and where untrusted input enters

smolvm runs an untrusted workload (an OCI image, a packed `.smolmachine`, or a bare Alpine
guest) inside a microVM with its own Linux kernel, on macOS (Hypervisor.framework), Linux
(KVM) and Windows (WHP), using libkrun as the VMM. The boundary we defend is **guest to host**:
code running inside the guest, including root there, must not reach the host beyond the
mounts, ports, network and forwarded capabilities the user explicitly gave the machine.

Treat these as attacker-controlled:

- **Everything the guest sends the host.** The guest agent (`crates/smolvm-agent`, started
  as PID 1 in the guest) speaks the protocol in `crates/smolvm-protocol` to the host over
  vsock; the host side is `src/agent/` (`client.rs`, `vsock_service.rs`, `fork/`,
  `live_ports.rs`, `live_resize.rs`, `pod_net.rs`, `terminal.rs`, `websocket.rs`, VNC and
  video). A compromised guest controls the agent, so every message, length, path, file name
  and exit code arriving from the guest is hostile. The agent's own hardening against the
  workload is guest-internal and matters much less than what the host does with its output.
- **Guest network traffic.** `crates/smolvm-network` runs a user-space TCP/IP stack
  (smoltcp) over the virtio-net frames the guest emits, relays TCP, UDP, ICMP and DNS to the
  host's sockets, publishes host ports into the guest, and enforces the egress policy
  (`--allow-host`, `--allow-cidr`, `--block-private`, `--allow-private`, `--deny-cidr`,
  `--allow-udp`, the cloud-metadata floor). `egress.rs`, `tcp_relay.rs`, `udp_relay.rs`,
  `dns_relay.rs`, `udp_publish.rs`, `tcp_listeners.rs`, `netns_tap.rs` and `fabric.rs` parse
  guest-originated bytes and decide what the host dials. `crates/smolvm-credentials` is a
  TLS-terminating interceptor that substitutes placeholder credentials for real ones in guest
  HTTPS requests; it must never leak the real value to the guest or send it to a host the
  rule did not name.
- **Guest CUDA calls (experimental).** `crates/smolvm-cuda`, `src/cuda_host.rs` and
  `src/cuda_daemon.rs` execute Driver and Runtime API calls on the host GPU that the guest
  shims (`smolvm-cuda-shim`, `smolvm-cudart-shim`, `smolvm-nvml-shim`, `smolvm-cuda-guest`)
  marshal over vsock. Handles, sizes and pointers in those messages are hostile.
- **Guest filesystem content on the host.** The guest's storage disk and overlay, anything
  the host extracts from them (`smolvm pack create --from-vm`, `machine cp` downloads,
  checkpoint capture in `src/portable_checkpoint.rs`, `crates/smolvm-checkpoint`), and the
  virtio-fs trees in `src/agent/virtiofs.rs` and `src/staged_mount.rs`.
- **Artifacts fetched or received from elsewhere.** OCI manifests, configs and layers
  (`crates/smolvm-registry`, `crates/smolvm-oci-layer`, `src/image_store.rs`,
  `src/image_seed.rs`), Docker-save and OCI-layout archives given to `--image`,
  `.smolmachine` packs and `.checkpoint` files (`crates/smolvm-pack`: `extract.rs`,
  `detect.rs`, `format.rs`, `checkpoint_stream.rs`, `macho.rs`, `signing.rs`;
  `src/pack_seed.rs`, `src/artifact_cache.rs`) and S3-backed volumes
  (`crates/smolvm-s3fs`, `src/remote_volume.rs`). A pack or image is often produced by a
  third party and must not read, write or execute anything on the host outside its
  extraction root.
- **Requests to the local HTTP API** (`src/api/`, `smolvm serve start`). The server has no
  authentication by design and listens on a Unix socket or loopback; the caller is trusted
  to run machines but is treated as *untrusted for anything beyond that*: request bodies
  may carry no resolvable secret reference (`from_env`, `from_file`), may not mount the
  protected host trees, and may not enable nested virtualization unless the server was
  started with `--allow-nested-virt`.
- **Clients of a published port** (`-p HOST:GUEST`) reach the guest service through the
  relay. The relay must not let them reach anything but that guest port.

Trusted (in the TCB): the invoking host user, the host OS, the hypervisor, libkrun and
libkrunfw (the `libkrun/` and `libkrunfw/` submodules and the prebuilt libraries under
`lib/`), and the Smolfile and command line the user wrote. `smolvm-sdk/` is a separate
repository and out of scope here.

## Components that matter most / least

Most important, in this order:

1. `src/agent/` and `crates/smolvm-protocol`: the host's handling of guest messages, file
   transfers (`machine cp`), exec and terminal streams, fork/branch and checkpoint restore.
2. `crates/smolvm-pack`, `crates/smolvm-oci-layer`, `crates/smolvm-registry`,
   `crates/smolvm-checkpoint`, `src/image_store.rs`, `src/portable_checkpoint.rs`: parsing
   of archives, manifests and checkpoints from untrusted sources, including path traversal,
   symlink and hard-link escapes, size and count limits, and digest verification.
3. `crates/smolvm-network` and `crates/smolvm-credentials`: the egress policy and the
   relays. A guest that reaches a destination the policy denied, or that learns a real
   credential, is a boundary failure.
4. `crates/smolvm-cuda` and `src/cuda_host.rs`: host-side execution of guest-marshalled GPU
   calls.
5. `src/api/` and `src/secrets.rs`: the API's refusal of secret references, protected
   mounts and nested virtualization; the resolution of secret references at launch.
6. `src/vm/`, `src/storage.rs`, `src/db*`, `src/pool.rs`: state under the user's data
   directory, including isolation between machines of the same user.
7. `crates/smolvm-shim` (containerd shim v2 for Kubernetes) and `src/agent/pod_net.rs`.

Less important: `crates/smolvm-agent` defects that only let the workload affect its own
guest; `crates/smolvm-smolfile` (user-authored input); the CLI argument handling in
`src/cli/`; `bench/`, `demo/`, `examples/`, `deploy/`, `packaging/`, `nix/`, `scripts/` and
`docs/`. `patches/` holds our patches to libkrun and libkrunfw; a flaw in one of those patches
is in scope, a flaw in upstream libkrun or the kernel is not (report it upstream).

## How to exercise it

The image is built as `.oss-scanner/Dockerfile` describes: a debug build of the whole
workspace with every test compiled, the guest agent also as a static musl binary under
`target/<arch>-unknown-linux-musl/release/smolvm-agent`, and the cargo cache populated so
`cargo test --offline` works.

- **Unit tests**: `cargo test --lib -p smolvm -p smolvm-pack -p smolvm-registry
  -p smolvm-protocol -p smolfile -p smolvm-cuda -p smolvm-s3fs`, plus
  `cargo test -p smolvm-agent --bins` and `cargo test -p smolvm-shim`. Run them as the
  unprivileged `scanner` user (`runuser -u scanner -- cargo test …`), as CI does: as root,
  checkpoint install takes the service's shared-base layout and
  `portable_checkpoint::tests::install_verifies_and_consumes_checkpoint` asserts the
  per-user one. The `smolvm-network` suite opens real sockets and parts of it hang on a
  plain Linux runner; run individual tests there by name. `SMOLVM_LIB_DIR` points at the
  prebuilt libkrun for this architecture. A test run leaves sparse machine disks under
  `~/.cache/smolvm` with an apparent size in the hundreds of GiB; remove that directory
  after a run.
- **Booting a machine needs `/dev/kvm`**, which this image does not have. `tests/` holds the
  integration suites (`run_tests.sh` and the `test_*.sh` and `test_*.py` files) and they will
  not run here. Prefer a Rust test against the crate API, or a crafted file fed to a
  host-side parser, over a reproducer that needs a running VM.
- **Parsers to feed**: pack and checkpoint extraction in `crates/smolvm-pack/src/extract.rs`
  and `checkpoint_stream.rs`; layer application in `crates/smolvm-oci-layer`; manifest and
  descriptor handling in `crates/smolvm-registry` and `src/image_store.rs`; frame decoding
  and policy evaluation in `crates/smolvm-network/src/{frame_stream,egress,dns,tcp_relay}.rs`;
  message decoding in `crates/smolvm-protocol`; API request handling in `src/api/handlers`.
  `target/debug/smolvm` is the CLI, and `smolvm pack` and `smolvm machine create --from`
  parse an artifact on the host before any VM is involved.

## How you rate severity

A finding counts when a guest, an artifact, a network peer or an API client can make smolvm
do something on the host that the documented model says it must not. State the host OS the
reproducer needs, the flags the machine was started with, and whether the defaults suffice; a
finding against the defaults weighs more than one that needs a capability forwarded.

- **Critical**: code execution, or an arbitrary file write, on the host from the guest or
  from a crafted image, pack or checkpoint. Memory corruption on the host reachable from the
  guest, including through the network relay, the agent protocol or the CUDA host.
- **High**: a host file read or write outside the configured mounts and the artifact's
  extraction root (path traversal, symlink or hard-link escape in a pack, layer or
  checkpoint; `machine cp` escaping its target). An egress policy bypass: reaching a denied
  CIDR or host, the cloud-metadata address under `--block-private`, or the host's loopback
  where it was denied; a real credential disclosed to the guest or sent to a host the rule did
  not name. One machine reading or altering another machine's disk, state or control socket
  under the same user. A secret reference resolved for an API client or a pack. A tampered
  release archive that the installer's checksum verification should reject and does not.
- **Medium**: denial of service of the host side that a guest or an artifact achieves cheaply:
  the VMM or `smolvm serve` process panicking or aborting, unbounded host memory or disk use
  (decompression bombs, unbounded manifests, unbounded relay buffers), or one machine
  stalling the API for all others. Host information disclosed to the guest beyond what the
  model documents.
- **Low**: a defect that needs a non-default option meant for trusted workloads
  (`--allow-system-mounts`, `--nested`, `--mount-socket`, a writable `--volume`); a panic
  confined to one CLI invocation on user-authored input; guest-internal hardening of the
  agent.

Not vulnerabilities: anything that presupposes a compromised host or a hostile local user on
the host; anything reached only through a capability the user forwarded and behaving as
documented (`--volume`, `--ssh-agent`, `--net`, published ports, `--mount-socket`); guest
behaviour with no host effect; the API having no authentication; release archives being
unsigned (documented). A guest escape in libkrun, libkrunfw or the guest kernel belongs
upstream unless it is in one of our `patches/`.

## Anything to leave alone

- Do not report the libkrun stub used in CI, the prebuilt binaries under `lib/`, or the
  contents of the `libkrun/`, `libkrunfw/` and `smolvm-sdk/` submodules.
- Do not report `unsafe` FFI into libkrun in `src/agent/krun.rs` and `launcher*.rs` unless
  guest-controlled data reaches it.
- Do not report that the HTTP API is unauthenticated, that `--volume` exposes the host
  directory, or that secrets are visible in the workload's environment; these are documented.
- Do not report the hosted smolmachines cloud control plane; it is operated separately.

## How to report

Send findings through GitHub private vulnerability reporting
(https://github.com/smol-machines/smolvm/security/advisories/new) or to the contact in the
enrolment. Give a reproducer that runs in this image: a Rust test, a crafted file and the
command that parses it, or the exact bytes sent to a parser, with the observed host effect.
Name the component, the host OS, and the flags the machine needs. A proposed patch should
keep the behaviour documented in `AGENTS.md` and `docs/` and add a test beside the fixed code.
