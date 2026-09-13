---
name: sandbox
description: Runs untrusted code in a throwaway smolvm microVM against a repo it must not modify, with no network unless explicitly granted, and collects artifacts from a writable output directory. Use when executing an agent's generated script, a pull request's test suite, or any code that should not be trusted with the host; when a workload needs egress granted one host at a time; or when a sandbox run has to be cancelled, because Ctrl-C leaves the VM running and invisible to the CLI. Do not use it for a development environment that is re-entered across sessions, for running a Docker daemon inside a machine, or for installing smolvm itself, which is the install packet.
---

# Running untrusted work in a throwaway machine

Verified on **smolvm v1.14.6** on macOS arm64 and Linux aarch64, 2026-09-10. Done means the command's output landed in your writable directory,
the repo is unchanged, the workload could not reach the network, and nothing is left running.

**Two smolvm defects shape this packet and you will meet both.**

- **[#1193](https://github.com/smol-machines/smolvm/issues/1193): Ctrl-C does not stop a cached
  run.** The VM outlives the CLI, `machine list` reports `No machines found`, and it exits only
  when the untrusted workload does. **The cancel is `scripts/cleanup.sh --cancel`, never Ctrl-C.**
- **[#1192](https://github.com/smol-machines/smolvm/issues/1192): on macOS a cached run with any
  mount never boots.** The offline shape below is therefore Linux-only today. macOS has its own
  page with a route that works: read `references/macos.md`.

## Workflow

```
- [ ] 1. preflight.sh, and read result= and device_budget_ok=
- [ ] 2. bake.sh          (offline route only; network on, nothing untrusted mounted)
- [ ] 3. run.sh           (the untrusted command; records the VM pid)
- [ ] 4. verify.sh        (from inside the guest and from the host)
- [ ] 5. cleanup.sh       (or cleanup.sh --cancel to stop a run early)
```

**1. Preflight.** Read-only: starts no VM, bakes nothing.

```bash
scripts/preflight.sh --mounts 2 --ports 0
```

`device_budget_ok=no` means the boot will fail with `no more IRQs are available`. The guest has
eleven IRQs: **four `-v` mounts boot and five do not, and every published port costs one of those
slots**, so the budget is mounts plus ports. Combine directories under one mount rather than
discovering this at boot.

`offline_shape=unavailable` means this host cannot run the shape below. On macOS that is #1192; on
any host it can also mean the bake helper's memory does not fit, which step 2 diagnoses.

**2. Bake the image. This is the only step that talks to a registry.**

```bash
scripts/bake.sh python:3.12-alpine
```

Network on, nothing untrusted mounted, done before the untrusted code is anywhere near the machine.
Afterwards the runs need no network at all, which is a materially stronger sandbox than granting
egress and hoping.

**3. Run the untrusted command.**

```bash
scripts/run.sh --repo ./repo --out ./out -- sh -c 'python3 /workspace/calc.py > /out/result.txt'
```

The repo is mounted read-only at `/workspace`, the output directory writable at `/out`, and the run
has no network. It prints `used_host_cache=yes`, which is the assertion that the bake worked and
that this run reached no registry: without it the run pulled, which means it had network, which
means it was not the sandbox you asked for.

It also prints `vm_pid=` and records it. **That pid is the only route back to the machine** if the
run has to be stopped.

To grant egress, name hosts one at a time:

```bash
scripts/run.sh --allow-host example.com --repo ./repo --out ./out -- <command>
```

**4. Verify. Both halves, because either alone passes on a broken sandbox.**

```bash
scripts/verify.sh --expect-file result.txt --expect 42
```

```
inside_workspace=ok (readonly)
inside_out=ok (writable)
inside_network=ok (blocked)
artifact=ok (42)
repo_unchanged=ok
result=sandbox_held
```

The inside half proves the workload could not write the repo and could not reach the network; the
host half proves the artifact came out and the repo is unchanged. A run that merely exited zero
tells you neither.

**5. Clean up, or cancel.**

```bash
scripts/cleanup.sh --purge            # after a run finished
scripts/cleanup.sh --cancel --purge   # to stop a run that is still going
```

`--cancel` kills exactly the VMs `run.sh` recorded and then verifies that nothing is left. It waits
before asserting an empty machine list, because the ephemeral entry retires after the run returns
and an immediate assertion fails on a healthy host.

## Cancelling, and why Ctrl-C is not it

On the offline route, interrupting the CLI leaves the VM running with no CLI route to it, and it
exits only when the untrusted workload finishes. For code that hangs or loops that is unbounded
exposure, with roughly 230 MB held per survivor.

**The routes differ, and `references/traps.md` has the measurements.** On the plain path a `SIGINT`
to the CLI does take the VM with it, verified here on Linux. Do not rely on that: interrupting the
*wrapper* rather than the CLI leaves both running on either route, which was observed on both hosts
used for this packet. Use `--cancel`.

## Reference pages

Read these when the situation calls for them; they are not needed for a normal run.

- **`references/traps.md`** for every trap with its measurement: the two routes and what Ctrl-C does
  to each, the bake helper's fixed memory, why `pgrep -f` and `readlink` both fail as reapers, and
  what counts as cache rather than residue.
- **`references/macos.md`** if you are on macOS. The offline shape does not work there; that page
  gives a route that does and says what it costs.
- **`references/windows.md`** if you are on Windows. The bake never completes there, so the offline
  shape is unavailable for a different reason, and the reaper has to be broader.

## Security defaults, and why they are the defaults

- **No network is the default because it is the only guarantee that does not depend on the
  workload's cooperation.** An egress policy is a filter on what untrusted code asks for; no network
  is a property of the machine. The bake exists so that the offline run is possible at all.
- **`--allow-host` grants one host, and the run still has a network stack.** Prefer it to `--net`,
  but treat it as a narrower opening rather than as no opening. A denial under it looks like a DNS
  failure, so a workload can fail confusingly rather than obviously.
- **The repo is `:ro` because a read-only mount is enforced by the guest kernel**, not by the
  workload's good behaviour. `verify.sh` tries to write it and asserts the write failed, then checks
  from the host that nothing landed.
- **The output directory is the only writable path out of the sandbox.** Keep it a directory you
  created for this run, not a source tree, and read what lands in it before trusting it.
- **Cleanup kills only the VMs this packet recorded.** A shared host can carry another session's
  machines, and one was live throughout the runs behind this packet; the reaper is scoped by the
  boot config's path and left it alone. A cleanup that kills every smolvm process is fine on your
  laptop and destructive on a build agent.
- **Nothing here escalates privilege**, edits smolvm configuration, or touches `~/.smolvm`. The
  scripts are wrappers over the public CLI.

## Platform arms

- **Linux aarch64**: **the offline route, the network-on route, the cancel path and the reaper
  were all run here on v1.14.6.** This is the first host on which the offline route completed.
- **Linux x86_64**: the offline route is verified in the material behind this packet, not re-run.
- **macOS arm64**: the offline shape is unavailable (#1192, reproduced here 3 of 3). The
  network-on route was run end to end. `references/macos.md`.
- **Windows x86_64**: the offline shape is unavailable for a different reason, the bake never
  completes. `references/windows.md`, **re-run on 2026-09-11 against v1.14.6** on Windows 11 Home
  build 10.0.26200.0 UBR 9445: the mount and the network-off refusal confirmed, and the bake still
  did not complete inside a ten minute cap.

## Eval prompts, and what they produced

Run on 2026-09-08 PT against v1.14.2 from the published release, under an isolated `HOME`, on
macOS 26.6.2 arm64 and Lima `linux-kvm` (Ubuntu 24.04 aarch64). Output is verbatim.

**1. "Run this untrusted script against my repo without letting it modify the repo or reach the
network, and get the output back."**

On Linux aarch64 the **offline route** answers this directly on v1.14.6, with the network off for
the whole run: `used_host_cache=yes`, `inside_network=ok (blocked)`, `artifact=ok (42)`,
`repo_unchanged=ok`, `result=sandbox_held`. On macOS, where #1192 blocks that route, the
network-on route:

```
route=network-on
vm_pid=74421
cli_exit=0

inside_workspace=ok (readonly)
inside_out=ok (writable)
inside_network=ok (REACHED)
artifact=ok (42)
repo_unchanged=ok
result=sandbox_held
```

`inside_network=REACHED` is the expected result on that route and the reason it is the second
choice: the network was open for the whole run.

**2. "The sandboxed job is hung. Stop it."**

On Lima, a run with a `sleep 600` workload, wrapper interrupted:

```
--- recorded pid file ---
76773 /home/<user>/skp/.cache/smolvm/vms/77196d36f7bb8555/boot-config.json
--- VM still alive after the interrupt? ---
STILL RUNNING 76773 ...
--- machine list after the interrupt ---
vm-1b3d157f running (eph)   4  2048 MiB  2  0  20 GiB  10 GiB
=== cancel with the packet reaper ===
cancelled=76773 config=/home/<user>/skp/.cache/smolvm/vms/77196d36f7bb8555/boot-config.json
machines=clean
vm_processes=none
result=clean
```

The same on macOS, cancelling pid 82510 and ending clean.

**3. "Can I sandbox on this machine?"**

macOS 26.6.2 arm64, where the answer is a qualified no:

```
platform=darwin-aarch64
accel=hypervisor_framework
accel_access=ok
offline_shape=unavailable
offline_shape_blocker=smol-machines/smolvm#1192
device_budget_ok=yes
cancel_route=scripts/cleanup.sh --cancel
result=blocked
```

and `bake.sh` refuses rather than baking something unusable:

```
result=unsupported_on_macos
A baked image is only useful to a run that also mounts something, and on macOS
--oci-cache plus any -v mount times out the boot (smol-machines/smolvm#1192).
```

## Re-verified on v1.14.6

Run 2026-09-10 PT against v1.14.6 from the published release. **Two things changed on this
release and both matter.**

**The offline route now runs on Linux, for the first time on any host available to this packet.**
On Lima `linux-kvm` (Ubuntu 24.04 aarch64) the bake completed in 59 s and the run held:

```
result=baked
Using cached image f60a20a837dc1a34 (host cache hit; no pull)
used_host_cache=yes
inside_workspace=ok (readonly)
inside_out=ok (writable)
inside_network=ok (blocked)
artifact=ok (42)
repo_unchanged=ok
result=sandbox_held
```

`inside_network=ok (blocked)` is the line the whole packet exists for: the workload reached no
network at all. Earlier releases could not get this far on any host here.

**The reaper was broken on exactly this route, and is fixed.** The pack-run path forks without
execing, so its VM child inherits the parent's argv and carries no `_boot-vm`. Measured on
v1.14.6 before the fix: `run.sh` reported `vm_pid=not_observed`, and after the CLI was killed
`cleanup.sh` reported `vm_processes=none` and `result=clean` while the VM held 234 MB. After the
fix, the same sequence reports `vm_pid=71676` and
`vm_process=... forked-under ...` with `result=vms_still_running`, and `--cancel` clears it. See
`references/traps.md`.

**macOS is unchanged**: `--oci-cache` with any mount still times out, 3 of 3 with both controls
passing in the same session, so the offline shape is still unavailable there and `bake.sh` still
refuses with the reason. The network-on route held (`artifact=ok (42)`, `result=sandbox_held`) and
the cancel path recorded and killed its VM.

## What was not run

- **The offline route on macOS.** Blocked by #1192, reproduced on v1.14.6 3 of 3 with both
  controls passing. `references/macos.md` gives the route that works there and what it costs.
  The offline route itself is now verified on Linux aarch64, so it is no longer unrun everywhere.
- **A GPU sandbox.** Nothing here was run against a GPU on either release.
- **The macOS first-choice route** in `references/macos.md`, which needs a `docker`, `crane`,
  `podman` or `nerdctl` binary to produce an image archive. None is installed on that host.
- **Windows.** One earlier run, recorded in `references/windows.md`.
- **S3 and `:staged` mounts**, and driving the sandbox from a CI runner.

## Related packets

- `install` for the boot this assumes and the KVM group check.
- `teardown` for the wider cleanup, and for what a leak check must exclude.
- A machine whose state should survive between runs is the opposite of this packet, and is a
  separate procedure.
