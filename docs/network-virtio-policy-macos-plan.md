# Policy-complete, cross-platform virtio-net

## Problem
The HTTP API accepts `ports` but always provisions TSI (outbound-only), so published/inbound
ports are silently non-functional through the API. virtio-net — the only backend with an
inbound path — is reachable only via the hidden `--net-backend virtio-net` CLI flag, is
Linux-only, and can't enforce egress policy (the `PolicyRequiresTsi` fallback). This closes
those gaps so virtio-net is a first-class, policy-complete, cross-platform backend.

## Decisions
1. DNS filtering on virtio-net **reuses** TSI's host-side filter (guest `dns_proxy` → vsock →
   `dns_filter_socket`) so semantics match by construction. Keep both backends.
2. Keep both backends — no convergence on one.
3. **TSI stays the default.** virtio-net is opt-in. Requesting `ports` without virtio-net is a
   clear error, not a silent break or an auto-switch.

## Architecture notes (verified)
- `plan_launch_network()` (`src/network/launch.rs`) is the single shared backend-decision
  chokepoint; both `launcher.rs` (CLI/fork) and `launcher_dynamic.rs` (the `_boot-vm` the API
  server spawns) call it with `port_count`.
- The published-port inbound relay lives only in the virtio-net path (`tcp_relay.rs`,
  `RelayTarget::Attached`); TSI has no inbound handling.
- `smolvm-network` is POSIX-only (`poll`/`pipe`/`fcntl`/`UnixStream`/`setsockopt` + userspace
  smoltcp) — Linux gating is incidental, not fundamental.
- libkrun `krun_add_net_unixstream` is `#[cfg(feature = "net")]` (not OS-gated); the macOS
  dylib is already built `NET=1`.
- TSI egress policy: the **DNS filter is host-side in smolvm** (reusable via vsock); the
  **CIDR filter is inside libkrun's TSI** (`set_egress`, `launcher.rs:569`) — TSI-only, so the
  gateway needs its own CIDR enforcement.

## Workstream A — egress policy on virtio-net
- A1. CIDR filter in the smoltcp gateway: enforce `allowed_cidrs` at host-connection setup;
  drop + RST disallowed destinations. Thread `allowed_cidrs` into `start_virtio_network`.
- A2. DNS filter: wire the existing `dns_filter_socket` + guest `dns_proxy` on the virtio-net
  launch path (same host-side filter code as TSI → exact parity, no reimplementation).
- A3. Integration: feed DNS-filter-resolved IPs (for allowed hostnames) into the gateway's
  dynamic allow-set so follow-up connections to resolved addresses pass A1.
- A4. Remove the `VirtioNet if has_policy → PolicyRequiresTsi` fallback in `launch.rs`.
- A5. Tests: allowed/blocked CIDR, allowed/blocked host, ports + `allowedCidrs` together.

## Workstream B — virtio-net on macOS
Correction after audit: virtio-net is **already cross-platform in source** — there is
nothing to un-gate.
- B1/B2 — N/A. `smolvm-network` is a main (cross-platform) dependency with no internal
  `cfg(target_os)`; the launcher's virtio-net arm and `create_unix_stream_pair`
  (`socketpair`) are not gated. The Linux-only dependency block holds only
  `seccompiler`/`landlock`.
- B3 — already handled: `SO_SNDBUF` over-request is non-fatal (logged, clamped); writes
  surface `EPIPE` rather than `SIGPIPE` (Rust ignores it process-wide on macOS too). No code
  change needed unless validation finds otherwise.
- B4. Confirm `lib/libkrun.dylib` exports `krun_add_net_unixstream` (NET=1 build) — same
  class of risk as the `krun_create_disk_overlay` vendoring gap.
- B5. Build this branch on the isolated `~/smolvm-f5` Mac clone (never touch
  `~/Documents/smolvm`) and live-validate virtio-net on HVF: outbound, CIDR, allow-host,
  published ports. Fix any runtime quirks that surface.

Remaining B work is pure Mac validation (B4 + B5); both require Mac access.

**VALIDATED on M4 Max / macOS 26.1 / HVF (2026-06-09, `~/smolvm-f5` fast-fork build):**
- B4: `lib/libkrun.dylib` exports `_krun_add_net_unixstream` (NET=1 build).
- virtio-net VM boots with `eth0 100.96.0.2/30` (smoltcp gateway active, not TSI).
- Outbound TCP works (`wget http://1.1.1.1/` succeeds) — the portable POSIX gateway +
  `krun_add_net_unixstream` + HVF move packets end-to-end.
- Inbound published-port host listener binds (`smolvm` holds `TCP localhost:18080 LISTEN`).
- Validated with the *base* virtio-net (fast-fork). The A+C egress-policy additions
  (`egress.rs`/`dns.rs`, CIDR + allow-host) are portable Rust with no `cfg(target_os)` and are
  Linux-live-validated; running them specifically on macOS needs this branch built on the Mac.

## Workstream C — API + UX (no default change)
- C1. Add `networkBackend: Option<NetworkBackend>` to `CreateMachineRequest`
  (`api/types.rs`); thread through `resource_spec_to_vm_resources` (`api/state.rs`, replacing
  hardcoded `None`).
- C2. Error when `ports` are requested without virtio-net (default or explicit TSI):
  "published ports require networkBackend: virtio-net".
- C3. Unhide `--net-backend`; `plan_launch_network` default stays TSI.
- C4. API tests: virtio-net + port reachable; TSI + port → clean 4xx.

## Workstream D — IPv6 dual-stack (DONE, live-validated 2026-06-10)
The gateway was IPv4-only by Phase-1 scoping, not by architecture. Now dual-stack:
- smoltcp `proto-ipv6` + `iface-max-addr-count-3`; gateway owns IPv4 + IPv6 ULA +
  EUI-64 link-local; default v6 route; `any_ip` covers v6 (verified in smoltcp 0.13).
- Link addressing: guest `fd53:4d00::2/64`, gateway `fd53:4d00::1` (`53:4d` = "SM",
  matching the MAC OUI scheme).
- `classify_guest_frame` handles `Ipv6Packet` (extension-headered frames pass through);
  outbound TCP relay is family-agnostic (V4-only guards removed).
- DNS socket binds wildcard `:53` — works over both families and transparently
  intercepts hardcoded external resolvers (TSI parity); AAAA records are learned into
  the egress allow-set alongside A (`dns::answer_ip_records`).
- `EgressPolicy` accepts v4 + v6 CIDRs; learned IPs are `IpAddr`.
- Published ports bind `[::1]` as well as `127.0.0.1` (v6 best-effort).
- Guest agent: optional `SMOLVM_NETWORK_{GUEST_IP6,GATEWAY6,PREFIX_LEN6}` env trio →
  rtnetlink `AF_INET6` addr (IFA_F_NODAD) + default route. Launchers export the trio.

**Validated live (Linux/KVM):** guest dual-stack (`fd53:4d00::2/64` NODAD + default via
gateway); NDP answered (gateway REACHABLE); guest TCP over v6 to a host ULA fetched
content end-to-end; v6 egress CIDR A/B (allow `fd7a::/48` → fetch OK; allow
`2001:db8::/32` → same target refused; v4 cross-family blocked); published port serves
both `127.0.0.1` and `[::1]` (explicit AF_INET6 client). AAAA learning unit-tested
(host lacks external IPv6 for a live allow-host→AAAA run).

Known remaining gaps (both families): general UDP relay (non-DNS UDP dropped), ICMP.

## Sequencing
A and B are independent (parallelizable). C depends on A removing the conflict. A is the
highest-value and fully testable on Linux; start there. D builds on A.
