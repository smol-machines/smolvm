# Lossless `smolvm serve` restart

## Goal

Restart the `smolvm` serve process (the node runtime / local API) — for a binary
upgrade **or** an unexpected crash-auto-restart — **without killing or orphaning
running VMs**, and reconnect to them afterward so exec / interactive / management
keep working.

This turns a fleet serve upgrade from a drain-everything operation into a rolling
`systemctl restart` that running workloads sail through.

## Scope — what "lossless" does and does NOT cover

The key distinction is **guest compute vs. host control-plane**. Processes
*inside* the VM (a job, a server, an agent task) live in the guest kernel, not in
serve, so they keep executing across a serve restart. What blips is the host-side
control channel for the ~1–3 s restart window: new exec/API calls fail and
**attached interactive sessions drop** (the WebSocket dies; the guest-side shell
process survives but the terminal must reconnect). Published-port traffic can blip
for that window too.

| Update type | Lossless? |
|---|---|
| **serve binary upgrade** (node runtime) | ✅ yes — the target win |
| serve **crash** / systemd auto-restart | ✅ yes (scopes cover it) |
| **libkrun upgrade** (hypervisor dylib) | ❌ no — only new VMs get it; running VMs keep the loaded copy |
| **host kernel / OS / instance reboot** | ❌ no — kills every host process, VMs included |
| guest rootfs / agent | ❌ no for running VMs (baked at boot) |

Infrastructure-level updates (libkrun, kernel, host reboot, instance replacement)
still bounce VMs — those need drain+reschedule today, and live-migration
(libkrun checkpoint/restore + the fork-clone work) long term. "Lossless restart"
≠ "survives anything."

## Why it's hard: three independent kill vectors

A running VM is, today, a child process of `smolvm-node.service` in that unit's
**delegated cgroup**. Three separate mechanisms tear it down on restart:

1. **serve signals the PID** — `impl Drop for AgentManager` (`src/agent/manager.rs`)
   calls `stop()` (SIGTERM/SIGKILL) when the manager owns the child and isn't
   `detached`. serve never detached on shutdown (the CLI does).
2. **systemd kills the service cgroup** — default `KillMode=control-group` SIGKILLs
   the whole subtree on unit stop. (`KillMode=process` mitigates; scopes make it moot.)
3. **systemd refuses to recreate the cgroup** — on `systemctl restart`, a surviving
   VM left in the service's delegated cgroup yields **`status=219/CGROUP`**: the new
   serve never starts and crash-loops. This fires on *any* unit (re)start, including
   systemd's automatic crash-restart.

Losslessness requires neutralizing all three plus reconnect. Missing any one still
kills the VM or crash-loops serve.

## The model: VMs become systemd scopes; serve becomes a reconnecting manager

Invert ownership: each VM becomes its own first-class systemd unit
`smolvm-vm-<id>.scope`, owned by PID1 in a **sibling cgroup** (not under the service).
serve *attaches to* and *detaches from* VMs instead of *containing* them — the
libvirt/`machined` pattern, and the supported way to put externally-forked
processes under systemd cgroup management.

```
serve.start_vm():
  fork _boot-vm  ──►  PID
  StartTransientUnit("smolvm-vm-<id>.scope", PIDs=[PID],
                     properties=[MemoryMax, CPUQuota, TasksMax, CPUWeight])
        └─ systemd adopts PID into a sibling cgroup + applies caps

serve dies / restarts:
  detach_all()  → Drop won't signal the PID            (vector 1)
  VM reparents to init; scope persists                 (systemd owns the cgroup)
  new serve starts in a CLEAN service cgroup           (no 219 — VM isn't there)

new serve startup:
  list_vms() (DB)  ✕  enumerate smolvm-vm-*.scope      (cross-check / reconcile)
  for each live VM: reconnect agent.sock + ping        (vector 3 → reconnect)

machine stop/delete:
  kill PID  →  scope auto-GCs when its last process exits   (no extra teardown)
```

Scopes auto-remove when empty, so stop/delete needs no special scope teardown —
killing the VM PID is enough and systemd reaps the scope.

## Plan (phased)

**Phase 1 — Scoped VM launch (`manager.rs`, core change).** After forking
`_boot-vm`, `busctl StartTransientUnit` creates `smolvm-vm-<id>.scope` adopting the
PID, with per-VM caps ported from the current cgroup code to scope properties.
**Availability gate + fallback** (`systemd_scope::is_available()`): requires
`/run/systemd/system` + `busctl` + **root** (system-bus `StartTransientUnit` needs
root/polkit; serve is root on the worker). Anything else — macOS dev, containers,
OpenRC, **or an unprivileged local Linux `serve`** — returns false and routes to the
existing delegated-cgroup placement, which keeps resource caps (just not lossless,
fine for dev). The root gate specifically prevents a non-root local serve from
entering scope-mode and then failing every adopt *uncapped* (scope-mode skips the
cgroup fallback). One detection point, two launch paths sharing everything
downstream. Accept the microsecond fork→adopt race (only risks a brand-new VM).
A runtime adopt failure *after* the gate passed (broken D-Bus) logs loudly; the VM
runs uncapped + not-restart-safe. Future: support the per-user bus (`busctl --user`)
for unprivileged local serve.

**Phase 2 — Detach on shutdown (DONE).** `ApiState::detach_all()` on serve's
non-drain shutdown path. Still required: scopes stop *systemd* from killing the VM;
detach is the only thing that stops serve's *application-level* signal.

**Phase 3 — Reliable reconnect.** `try_connect_existing` (connect `agent.sock` +
`ping`) works once serve actually starts; add a supervisor **retry loop** (bounded
backoff) for "alive but not yet reachable" machines so reconnect absorbs agent
settle time. Cross-check DB vs. enumerated scopes and reconcile drift.

**Phase 4 — Drain decoupling.** Remove `SMOLVM_DRAIN_ON_SHUTDOWN` from the worker
unit + Terraform. Preserve clean decommission via an **explicit control-driven
drain**: the autoscaler calls a serve drain trigger before `provider.terminate()`.
Drain becomes a deliberate decommission step, never a restart side-effect.

**Phase 5 — Crash-restart.** Falls out for free: with VMs in scopes, systemd's
automatic restart of a crashed serve also starts clean and reconnects. (This is why
a self-re-exec trick is insufficient — it covers only planned upgrades.)

**Phase 6 — Validation (gate before fleet rollout).** Idle VM survives a
`systemctl restart` (same PID) + reconnect + exec, ×3. Busy VM: restart while an
interactive exec streams → VM survives, session drops, fresh exec reconnects. Crash
sim: `kill -9` serve → auto-restart → survive + reconnect. Caps enforced on the
scope. Fallback: macOS/non-systemd still boots via direct fork.

**Phase 7 — Rollout.** Deploy to workers (one-time bounce — legacy VMs in the old
service cgroup still drop on that first restart); new VMs launch in scopes; every
subsequent restart is lossless. Codify unit/TF changes.

## Decisions & trade-offs

| Decision | Choice | Why |
|---|---|---|
| Scope vs hand-rolled cgroup move | **Scope** | Supported API; hand-moving fights `Delegate=` and is systemd-version-fragile |
| Scope vs self-re-exec | **Scope** | re-exec misses crash-restart; scopes cover both |
| Scope vs separate `vmd` daemon | **Scope** | daemon-split is the same losslessness at ~3× the architecture; revisit only if API/VM need independent scaling |
| fork-then-adopt race | **Accept** | window is microseconds, only risks a brand-new VM |
| non-systemd hosts | **Fallback to direct fork** | contains systemd coupling to the cloud worker; keeps dev/CI working |

## Risks

- **Blast radius** — touches the most critical path (VM spawn). Mitigate with the
  dual-path fallback (dev unaffected) and the Phase 6 validation gate.
- **systemd version differences** in scope/property semantics — pin behavior in an
  integration test on the actual worker image.
- **Reconnect to a busy VM** — the guest agent must tolerate a client vanishing
  mid-stream (the accept-loop design suggests it does; Phase 6's busy-VM test proves it).

## Status

- **Phases 1 + 2 implemented + validated live on worker-1 (2026-06-14).** A VM was
  placed (landed in `smolvm-vm-<id>.scope`, a sibling cgroup), serve restarted, and:
  VM PID survived; the scope stayed `active`; serve started clean (**no
  `219/CGROUP`**); `reconnected to machine ... pid=Some(<vm>)` (the live VM, not a
  stale record); and exec returned `LOSSLESS_OK_x86_64` (exit 0, 38 ms) through the
  reconnected serve. Scope binary sha `921eb504`.
- New `src/systemd_scope.rs` (busctl `StartTransientUnit`, no D-Bus crate);
  `serve.rs` chooses scope-mode when systemd is present (else delegated-cgroup
  fallback); `manager.rs` adopts the forked PID after fork. `internal_boot.rs`
  needed no change (it already skips self-placement when `SMOLVM_CGROUP_ROOT` is
  unset).
- **Phase 3 (reconnect retry) is now optional** — validation showed the existing
  `try_connect_existing` reconnects immediately once serve can start; the retry
  loop is belt-and-suspenders, not load-bearing.
- **Phase 4 code DONE (compiles):** explicit drain trigger — smolvm `POST /drain`
  (`handlers::machines::drain_node` → `drain_machines`, control-only via the mTLS
  listener); smolfleet `RuntimeDriver::drain()` (default no-op) + `SmolvmDriver`
  POST impl; autoscaler drains before `provider.terminate()` (best-effort, never
  blocks decommission). Ops half (remove `SMOLVM_DRAIN_ON_SHUTDOWN` from units + TF)
  pairs with the Phase 7 binary rollout.
- Pending: Phase 3 (optional retry hardening), Phase 4 ops (env removal), Phase 6
  busy-VM + crash-sim live cases, Phase 7 PR + fleet rollout. Code uncommitted
  across both repos; worker-1 reverted to fleet-standard `d8f57614`. See task #210.
