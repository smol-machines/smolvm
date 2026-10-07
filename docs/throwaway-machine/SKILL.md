---
name: throwaway-machine
description: Runs untrusted code in a throwaway smolvm microVM against a repo it must not modify, with no network unless explicitly granted, and collects artifacts from a writable output directory. Use when executing an agent's generated script, a pull request's test suite, or any code that should not be trusted with the host; when a workload needs egress granted one host at a time; or when a run has to be cancelled, because Ctrl-C on the wrapper script leaves the VM running, and on releases before v1.20.2 so does Ctrl-C on the CLI. Do not use it for a development environment that is re-entered across sessions, for running a Docker daemon inside a machine, or for installing smolvm itself, which is the install packet.
---

# Running untrusted work in a throwaway machine

Verified on **smolvm v1.23.0** on macOS arm64, 2026-10-04, by the offline route, the network-on route
and the cancel; on Linux aarch64 by the offline route and the cancel on v1.20.2, 2026-09-29, and the
network-on route on v1.18.2, 2026-09-24. Done means the command's output landed in your writable directory,
the repo is unchanged, the workload could not reach the network, and nothing is left running.
The Linux runs used the scripts of their date; this version's preflight, run and cleanup scripts
ran on Linux aarch64 on v1.22.2 on 2026-10-03.

**The cancel is `scripts/cleanup.sh --cancel`, never Ctrl-C**: on `run.sh` Ctrl-C leaves the CLI
and its VM running on v1.20.2 too, as "Cancelling" below measures.

Two issues shaped this packet and **v1.20.2 fixed both on macOS and Linux**; older releases still
have them:

- **[#1193](https://github.com/smol-machines/smolvm/issues/1193)**, fixed in v1.20.2: before it,
  a cached run's VM outlives an interrupted CLI, invisible to `machine list`.
- **[#1192](https://github.com/smol-machines/smolvm/issues/1192)**, fixed in v1.20.2: before it, a
  cached run with any mount never boots on macOS; `references/macos.md` gives the older releases a
  route.

## Workflow

**If you have no script to isolate, make one.** A file that reads a path under `/workspace`, tries
to create a file there, and tries to fetch a URL proves all three properties in one run, and the
three lines it prints are the evidence. An agent with an empty directory and no fixture stopped and
asked the user instead of building one.

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

`device_budget_ok=no` means the boot will fail with `no more IRQs are available`. On x86_64
through v1.22.2 the guest has eleven IRQs: **four `-v` mounts boot and five do not, and publishing
any port, or granting egress, adds one device**. arm64 guests have 128, and the preflight prints
`device_budget_ok=not_limiting` there. v1.23.0 ships a libkrun whose x86_64 guests have IRQs 5 to 23
(#1521); its ceiling was not measured, and the preflight applies the budget through v1.22.2 only.
Combine directories under one mount rather than discovering this at boot.

`offline_shape=unavailable` means this host cannot run the shape below: macOS before v1.20.2
(#1192), or Windows. The preflight cannot see whether the 8192 MiB bake helper fits; `bake.sh`
finds that out in step 2 and says so.

**2. Bake the image. This is the only step in which a machine has a network.**

```bash
scripts/bake.sh python:3.12-alpine
```

Network on, nothing untrusted mounted, done before the untrusted code is anywhere near the machine.
Afterwards the runs' machines need no network at all, which is materially stronger isolation than
granting egress and hoping. The host CLI still asks the registry for the image's manifest on every
`--oci-cache` run, to authorize the pull and to notice a tag that moved, so the host needs to reach
the registry; the workload does not.

**3. Run the untrusted command.**

```bash
scripts/run.sh --repo ./repo --out ./out -- sh -c 'python3 /workspace/calc.py > /out/result.txt'
```

The repo is mounted read-only at `/workspace`, or at the path `--repo-path` names, the output
directory writable at `/out`, and the run has no network. It prints `used_host_cache=yes`, which
is the assertion that the bake worked and that this run's machine pulled nothing: without it the
guest pulled, which means it had network, which means it was not the isolation you asked for.

It also prints `vm_pid=` and records it. **That pid is the only route back to the machine** if the
run has to be stopped.

**A script that is not in the repo** goes into the output directory before the run, and the
command calls it from there, as `sh /out/check.sh`. The output directory is the one path the run
can write, so nothing else on the host is exposed, and the repo stays unchanged.

To grant egress, name hosts one at a time:

```bash
scripts/run.sh --allow-host example.com --repo ./repo --out ./out -- <command>
```

**4. Verify. Both halves, because either alone passes when the isolation is broken.**

```bash
scripts/verify.sh --expect-file result.txt --expect 42
```

```
inside_workspace=ok (readonly)
inside_out=ok (writable)
inside_network=ok (blocked)
artifact=ok (42)
repo_unchanged=ok
result=isolation_held
```

The inside half proves the workload could not write the repo and could not reach the network; the
host half proves the artifact came out and the repo is unchanged. A run that merely exited zero
tells you neither.

`verify.sh` probes the shape without a grant. After a run with `--allow-host`, its
`inside_network` line does not describe that run's egress.

`--expect` takes one value and compares it with the whole file, newlines removed. For output of
several lines, have the command write the one value to check into a file of its own and name that
with `--expect-file`, or leave `--expect` off and the step checks only that the file is there and
not empty. The repo check looks for the step's own probe file; it does not compare the repo's
other files.

**5. Clean up, or cancel.**

```bash
scripts/cleanup.sh --purge            # after a run finished
scripts/cleanup.sh --cancel --purge   # to stop a run that is still going
```

`--cancel` kills exactly the VMs `run.sh` recorded and then verifies that nothing is left. It waits
up to 20 seconds, polling, before asserting an empty machine list, and says so, because the ephemeral entry retires
after the run returns and an immediate assertion fails on a healthy host.

## Looking around by hand

To inspect the repo interactively under the same isolation, open a shell in a throwaway machine
with the repo read-only and no network:

```bash
smolvm machine run -it --image alpine -v "$PWD/repo:/workspace:ro" -- /bin/sh
```

`exit` ends the shell and the machine. On v1.23.1 on macOS arm64, inside it `cat` read the repo,
`touch /workspace/x` gave `Read-only file system` and `wget` gave `bad address 'example.com'`; after
`exit`, `machine list` printed `No machines found` and no smolvm process was left.

## Cancelling, and why Ctrl-C is not it

On v1.20.2, Ctrl-C or `SIGKILL` on the CLI itself ends the VM within a second on both routes, on
macOS arm64 and Linux aarch64. **Interrupting `run.sh` is not a cancel**: the CLI it backgrounds
ignores `SIGINT`, so Ctrl-C on the script left the CLI and its VM running on the offline route on both
hosts, and killing the script alone left them on either route. For code that hangs or loops that is
unbounded exposure.

Before v1.20.2 the offline route is worse: interrupting the CLI itself leaves the VM running with no
CLI route to it, roughly 230 MB held per survivor (#1193). `references/traps.md` has the
measurements for each release and route. Use `--cancel`.

## If the workload brings up a VPN

A guest that runs Tailscale or another carrier NAT VPN loses its gateway and its resolver on the
default virtio-net link, and every lookup then fails as `bad address`, which reads like the
allow list rather than a routing clash. `--allow-host` and `--allow-cidr` select that link, so
this applies to any run here that grants egress. Move the link with `--guest-subnet`, passed to
`smolvm machine run` directly:

```bash
smolvm machine run --allow-host example.com --guest-subnet 10.200.0.0/30 --image alpine -- <command>
```

**`--guest-subnet` implies `--net`**, so never add it to an offline run: it opens the network the
offline route exists to keep shut. Pick a range outside `100.64.0.0/10`; the CLI accepts one inside
it without a warning. `references/traps.md` has the measurement.

## Reference pages

Read these when the situation calls for them; they are not needed for a normal run.

- **`references/traps.md`** for every trap with its measurement: the two routes and what Ctrl-C does
  to each, the bake helper's fixed memory, a guest VPN taking the default link, why `pgrep -f` and
  `readlink` both fail as reapers, and what counts as cache rather than residue.
- **`references/macos.md`** if you are on macOS with a release before v1.20.2. The offline shape
  does not work there; that page gives a route that does and says what it costs.
- **`references/windows.md`** if you are on Windows. The bake never completes there, so the offline
  shape is unavailable for a different reason, and the reaper has to be broader.

## Security defaults, and why they are the defaults

- **No network is the default because it is the only guarantee that does not depend on the
  workload's cooperation.** An egress policy is a filter on what untrusted code asks for; no network
  is a property of the machine. The bake exists so that the offline run is possible at all.
- **`--allow-host` grants a name and its subdomains, and the run still has a network stack.**
  `--allow-host-pattern` grants the exact name only. Prefer either to `--net`, but treat it as a
  narrower opening rather than as no opening. A denial under it looks like a DNS
  failure, so a workload can fail confusingly rather than obviously.
- **The repo is `:ro` because a read-only mount is enforced by the guest kernel**, not by the
  workload's good behaviour. `verify.sh` tries to write it and asserts the write failed, then checks
  from the host that nothing landed.
- **The output directory is the only writable path out of the machine.** Keep it a directory you
  created for this run, not a source tree, and read what lands in it before trusting it.
- **Cleanup kills only the VMs this packet recorded.** A shared host can carry another session's
  machines, and one was live throughout the runs behind this packet; the reaper is scoped by the
  boot config's path and left it alone. A cleanup that kills every smolvm process is fine on your
  laptop and destructive on a build agent.
- **Nothing here escalates privilege**, edits smolvm configuration, or touches `~/.smolvm`. The
  scripts are wrappers over the public CLI.

## Platform arms

- **Linux aarch64**: **the offline route and the cancel path on both routes were run here on
  v1.20.2**, 2026-09-29; the network-on route end to end on v1.18.2, and once on v1.22.2.
- **Linux x86_64**: the offline route was verified on v1.14.2 on an NVIDIA A10 cloud host, not
  re-run since.
- **macOS arm64**: **the offline route, the network-on route and the cancel path on both were run
  here on v1.23.0**, 2026-10-04. Before v1.20.2 the offline shape is unavailable (#1192, reproduced
  3 of 3 on v1.18.2), and `references/macos.md` gives the routes run on v1.18.2.
- **Windows x86_64**: the offline shape is unavailable for a different reason, the bake never
  completes. `references/windows.md`, **re-run on 2026-10-03 against v1.22.2** on Windows 11 Home
  build 10.0.26200 UBR 9457: the mount, the artifact directory and the network-off refusal
  confirmed, the bake still did not complete inside a five minute cap in any of four shapes, and a
  plain foreground run interrupted by Ctrl-C or a kill left its VM running.

## Eval prompts, and what they produced

**1. "Run this untrusted script against my repo without letting it modify the repo or reach the
network, and get the output back."**

The offline route on macOS arm64, with the network off for the whole run; this is v1.20.2's output,
and v1.22.2 and v1.23.0 gave the same values:

```
route=offline
egress=none
used_host_cache=yes
inside_workspace=ok (readonly)
inside_out=ok (writable)
inside_network=ok (blocked)
artifact=ok (42)
repo_unchanged=ok
result=isolation_held
```

On macOS before v1.20.2, where #1192 blocks that route, the network-on route gives the same values
with `inside_network=ok (REACHED)`, which is the reason it is the second choice: the network was
open for the whole run.

**2. "The isolated job is hung. Stop it."**

With a `sleep 600` workload and the wrapper interrupted, the VM was still listed as running, and
`scripts/cleanup.sh --cancel --purge` ended it:

```
cancelled=76773 config=/home/<user>/skp/.cache/smolvm/vms/77196d36f7bb8555/boot-config.json
machines=clean
vm_processes=none
result=clean
```

That is Lima on v1.14.2, on the network-on route. On the offline route the VM is a forked child, and
on v1.22.2 and v1.23.0 on macOS the same cancel printed `cancelled=<pid> config=forked-under
<HOME>/.smolvm`.

**3. "Can I run untrusted code on this host?"**

On macOS arm64 on v1.23.0 the preflight says `offline_shape=available` and `result=ready`. Before
v1.20.2 it says `offline_shape=unavailable`, `offline_shape_blocker=smol-machines/smolvm#1192` and
`result=blocked`, and `bake.sh` refuses with `result=unsupported_on_macos` rather than baking
something unusable.

## Re-verified on v1.23.0

Run 2026-10-04 PT against v1.23.0 from the published release, checksum checked, under a fresh
isolated `HOME` on macOS 27.0.1 arm64, once. On Lima `linux-kvm` (Ubuntu 24.04 aarch64) the
checks named below ran once, so the Linux stamp stays on its earlier release.

**macOS: every step on both routes.** The preflight said `result=ready`, `offline_shape=available`
and `device_budget_ok=not_limiting`, `bake.sh` `baked in 5s` and `result=baked`, the offline run
`used_host_cache=yes`, and `verify.sh` gave `inside_workspace=ok (readonly)`, `inside_out=ok
(writable)`, `inside_network=ok (blocked)`, `artifact=ok (42)`, `repo_unchanged=ok` and
`result=isolation_held`. A run granted `--allow-host example.com` reached it, and the network-on
route gave `inside_network=ok (REACHED)` with the rest unchanged. `cleanup.sh --cancel --purge`
reported `cancelled=<pid> config=forked-under <HOME>/.smolvm` and `result=clean`. The persistent
machine with no network in `README.md` booted `python:3.12-alpine` with the repo read-only.

Linux aarch64: the same persistent machine with no network started in 12 s, the guest's `touch`
on `/workspace` gave `Read-only file system`, `wget` gave `bad address 'example.com'`, and `42`
reached the output directory. The offline route ran end to end: `baked in 72s`,
`used_host_cache=yes`, `inside_network=ok (blocked)`, `artifact=ok (42)`, `repo_unchanged=ok`
and `result=isolation_held`.

## Re-verified on v1.22.2

Run 2026-10-03 PT against v1.22.2 from the published release, checksum checked, under an isolated
`HOME` on macOS 27.0.1 arm64, twice, the second time from a fresh `HOME`. On Lima `linux-kvm`
(Ubuntu 24.04 aarch64) on 2026-10-03 guests above 2048 MiB timed out, so the Linux lines below are
a single run and the Linux stamp stays on its earlier release.

**macOS: every step on both routes.** The preflight said `result=ready` and `offline_shape=available`,
`bake.sh` `result=baked`, the offline run `used_host_cache=yes`, and `verify.sh` gave
`inside_workspace=ok (readonly)`, `inside_out=ok (writable)`, `inside_network=ok (blocked)`,
`artifact=ok (42)`, `repo_unchanged=ok` and `result=isolation_held`. A run granted
`--allow-host example.com` reached it, and the network-on route gave `inside_network=ok (REACHED)`
with the rest unchanged. `cleanup.sh --cancel --purge` reported `cancelled=<pid>` and
`result=clean`. Ctrl-C and `SIGKILL` on the CLI of a cached run with a mount ended the VM within a
second; Ctrl-C to `run.sh`'s process group left the CLI and its VM alive on the offline route and
not on the network-on route, as on v1.20.2. Once in five bakes, the first, `bake.sh` printed
`hdiutil create failed - Resource busy` and still `result=baked`; the run that followed used the
cache.

**Linux aarch64, single run.** The network-on route held with `inside_network=ok (REACHED)` and
`artifact=ok (42)`. The offline route did not run: the bake's helper takes 8192 MiB, `bake.sh`
said so, and its control boot at 2048 passed.

## Re-verified on v1.20.2

Run 2026-09-29 PT against v1.20.2 from the published release, checksum checked, under an isolated
`HOME`, on macOS 27.0.1 arm64 and Lima `linux-kvm` (Ubuntu 24.04 aarch64).

**macOS: #1192 is fixed.** The command from the issue, `machine run --net -v <dir>:/tmp --oci-cache
--image alpine:latest -- date`, passed 3 of 3, every row of the table in `references/macos.md`
passed 3 of 3, and the offline route ran end to end with the values shown in eval 1.

**Linux aarch64: the offline route ran**, the last time it has on Linux: `bake.sh` reported
`baked in 39s` and `result=baked`, then `used_host_cache=yes`, `inside_network=ok (blocked)`,
`artifact=ok (42)`, `repo_unchanged=ok` and `result=isolation_held`.

**#1193 is fixed, and the wrapper still orphans.** On both hosts a `sleep 600` run's VM was gone
within a second of Ctrl-C or `SIGKILL` on the CLI, on both routes, with `machine list` empty. Ctrl-C
to `run.sh`'s process group left the VM alive on the offline route on both hosts and on the
network-on route on Linux, and killing `run.sh` alone left it alive on both routes on both hosts;
`cleanup.sh --cancel --purge` reported `cancelled=<pid>` and `result=clean` every time.

## What was not run

- **The offline route on Linux on v1.18.2 and v1.22.2.** The Lima `linux-kvm` host could not boot
  the bake helper's 8192 MiB in time on those releases; it ran on v1.20.2 and v1.23.0. The branch
  of `bake.sh` that reports a helper too large for the host ran on v1.23.0 only against a stub
  that failed the bake, not on a host that could not boot the helper.
- **A GPU workload.** Nothing here was run against a GPU on either release.
- **The macOS second-choice route** in `references/macos.md` since v1.16.1. An agent following
  this packet ran it on macOS arm64 on v1.16.1, 2026-09-15, with an archive built by `crane`
  0.22.1; it has not been re-run since, and the `docker save` form on that page was not run.
- **Windows, the cancel scripts.** `scripts/*.sh` do not run there; `references/windows.md` has the
  measurements a port would need.
- **S3 and `:staged` mounts**, and driving the packet from a CI runner.

## Related packets

- `install` for the boot this assumes and the KVM group check.
- `teardown` for the wider cleanup, and for what a leak check must exclude.
- `dev-env` when state should survive between runs, which is the opposite of this packet.
