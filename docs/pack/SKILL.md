---
name: pack
description: Turns an image, or a machine already provisioned, into a single self-contained artifact that runs on another compatible host. Use when shipping a prepared environment as one file, when a packed artifact runs but the state installed into it is missing, when pack create fails because the VM it boots to pull or export could not start, when an older release refuses to export a branched machine, or when deciding whether to pack from an image or from a machine. Do not use it to keep a machine you re-enter, which is the dev-env packet, or to run untrusted code, which is the throwaway-machine packet.
---

# Packing a machine into a portable artifact

Verified on **smolvm v1.22.2** on macOS arm64, 2026-10-03, and on **v1.14.6** on Linux aarch64,
2026-09-11; the Linux host could not run the packing steps on v1.18.2 or v1.22.2, for the reason in
"Platform arms". Done means the artifact runs a command in a real VM and, for a machine pack, **the state you installed is still
inside it**.
The Linux runs used the scripts of their date; this version's preflight and cleanup scripts ran
on Linux aarch64 on v1.22.2 on 2026-10-03.

**The assertion that matters is a value, not a boot.** A pack that lost its rootfs still boots,
still prints a guest kernel and still exits zero. The only thing that separates a good artifact
from an empty one is a marker written into the source machine before packing and read back out of
the artifact afterwards, which is what `pack-machine.sh` and `verify-pack.sh` do between them.

## Procedure

**1. Preflight.** Read-only: starts no VM, packs nothing.

```bash
scripts/preflight.sh
```

The lines to read are `exporter_memory_ok` and `image_vm_memory_ok`. Both pack paths boot a
helper VM before they write anything. `pack create --image` pulls the image in a VM fixed at 4
vCPUs and 8192 MiB on every release here. `pack create --from-vm` boots an export helper: fixed at
8192 MiB through v1.16.1, when a host that could not seat it failed with `agent did not become
ready within 30 seconds`, which mentions neither memory nor the helper; from v1.16.2 it asks for
4096 MiB (on Linux half of the available memory when that is less, never under 1024),
`SMOLVM_EXPORT_HELPER_MEMORY_MIB=<MiB>` sets it, and a failed start says `The export helper asked
for N MiB of memory` and names the variable. `exporter_memory_mib` is the figure this binary will
ask for, except under a cgroup memory limit on Linux, where smolvm asks for less. Both lines are
warnings and not gates, because the figures are caps rather than reservations: see "What the
memory lines do and do not promise". From v1.16.1 the export helper reuses the machine's cached
image layers instead of pulling the image again and prints `Reusing
the machine's cached image layers...`; on macOS arm64 on v1.16.1 that export completed in 1.2 s
with `exporter_memory_ok=no` reported by the same preflight moments earlier, 2026-09-15.

**2. Pack from an image**, when you want a runnable artifact of a stock image.

```bash
scripts/pack-image.sh                       # alpine, ./from-image
scripts/pack-image.sh python:3.12-alpine ./mypack
```

This path boots the 8192 MiB pull VM, so `image_vm_memory_ok` is its line; `--mem` sets the
artifact's memory and does not reach that VM. **If you pass a custom output, pass it to the
verify step too** (`verify-pack.sh --image ./mypack`), or that step finds nothing at its defaults
and tells you so rather than passing.

**3. Pack from a machine you provisioned**, when the point is the state in it.

```bash
scripts/pack-machine.sh                     # smolskill-golden, ./from-vm
```

It creates the machine with a workload that stays up, waits for a value from it, writes a marker,
**asserts the marker on the source**, stops the machine and exports it. The source assertion is
not ceremony: packing a machine whose provisioning silently failed produces an artifact that runs
perfectly and contains nothing, and nothing downstream will tell you.

**Packing a machine that already exists**, the user's own rather than one `pack-machine.sh` made:
the script refuses any name without the `smolskill-` prefix, so run its sequence by hand. **Stop
the machine first**: `--from-vm` packs a stopped machine's snapshot and refuses a running one. A
`machine start` afterwards is how the machine comes back. A machine provisioned by hand is verified
with a file of the user's own: `--marker-path` names it and `--marker` its expected last line.

```bash
smolvm machine exec --name myapp -- tail -1 /root/provisioned.txt   # note the value on the source
smolvm machine stop --name myapp
smolvm pack create --from-vm myapp --output ./myapp-portable --single-file   # one file, no sidecar
scripts/verify-pack.sh --machine ./myapp-portable --marker-path /root/provisioned.txt --marker <that value>
smolvm machine start --name myapp                                    # the machine comes back
```

With no file of the user's to check, write the packet's marker before the stop,
`smolvm machine exec --name myapp -- sh -c 'echo PACKED_STATE_PRESENT > /marker.txt'`, verify
without `--marker-path`, and remove `/marker.txt` after the start.

`verify-pack.sh --machine` reads the marker out of a `--single-file` artifact as it does from a stub
with a sidecar. With no image artifact beside it, expect `image_pack=skipped` and
`result=artifacts_good (1 of 2 artifacts)`; the `what the artifact says it is` block reads the
sidecar, so a single file prints none.

**4. Verify.** Both halves.

```bash
scripts/verify-pack.sh
```

```
image_pack_is_a_vm=ok (Linux)
image_pack_second_run=ok (SECOND_RUN_OK)
pack_cache_entries=2
image_pack_reused_cache=ok (2)
machine_pack_carried_rootfs=ok (PACKED_STATE_PRESENT)
machine_pack_is_a_vm=ok (Linux)
result=artifacts_good (2 of 2 artifacts)
```

`machine_pack_carried_rootfs` is the load-bearing line. The rest is context.

**Verifying nothing is not a pass.** Point it at artifacts that are not there and it says
`result=nothing_verified` and exits non-zero, because a green line over zero artifacts is the same
false clean the marker exists to prevent.

**5. Clean up.**

```bash
scripts/cleanup.sh --purge --artifacts ./from-image ./from-vm
```

`cleanup.sh` waits up to 20 seconds, polling the machine list, and prints `waiting=up to 20s`
first: an ephemeral machine's entry retires after its run returns.

It prunes each recorded machine while it still exists, deletes it, removes both stubs and their
sidecars, and runs `pack prune`, which keeps the five most recently used extractions, so the two
this procedure made stay; `smolvm pack prune --all` removes every unused one, theirs included.
**`smolvm machine prune` with no argument does not run on this release**; the form is
`--name <NAME>`.

## Forwarding the SSH agent to an artifact

From v1.18.1 the artifact's own `run` and `start` take `--ssh-agent`, the same bridge `machine
run` has: the guest gets `SSH_AUTH_SOCK=/tmp/ssh-agent.sock` and the host agent signs, so no key
enters the artifact or the VM.

```bash
./from-image run --net --ssh-agent -- sh -c 'apk add -q openssh-client; ssh-add -l'
./from-image start --net --ssh-agent
./from-image exec -- sh -c 'apk add -q openssh-client; ssh-add -l'
```

Measured on macOS arm64 on v1.18.2 with a throwaway key in a throwaway agent, and the artifact's
own `run --ssh-agent` again on v1.22.2: both forms listed that key's fingerprint from inside the
guest, a `run` without the flag had `SSH_AUTH_SOCK` unset, and with the host variable empty the flag stops before booting with
`--ssh-agent: SSH_AUTH_SOCK is not set. Start an SSH agent with: eval $(ssh-agent) && ssh-add`.
**Forward the agent only to an artifact you trust**: the guest can ask for signatures for as long
as it runs, and an artifact is a filesystem somebody else prepared.

## What an artifact is, and what it carries

A pack is **two files**: a stub binary and a `<stub>.smolmachine` sidecar. `--output` names the
**stub**; the sidecar is created for you. Keep them together.

```
Mode:       container
Image:      python:3.12-alpine
Platform:   linux/arm64
CPUs:       4
Memory:     8192 MiB
Checksum:   94baf297
```

That `Memory` is the **packed artifact's** runtime memory, which `pack create --mem` can set. It
is not the export helper's, which `SMOLVM_EXPORT_HELPER_MEMORY_MIB` sets from v1.16.2, nor the
image pull VM's, which is fixed at 8192 MiB.

A machine pack carries the root filesystem and the workload settings. It does not carry
`/workspace`, which lives on the storage disk, unless `pack create --from-vm --include-workspace`
is passed, nor host mounts, remote volumes, credential bindings (`pack create` warns about the
last two), or the source machine's CPU and memory sizes.

## What the memory lines do and do not promise

A helper VM's memory is a **cap, not a reservation**, so a host reporting less available memory
can still pack. Measured on v1.14.6, when the export helper was fixed at 8192 MiB: the export
succeeded on a Mac whose preflight reported `free_memory_mib=4990`, and on v1.16.1 an export
completed in 1.2 s with `exporter_memory_ok=no`. On a small Linux host the fixed figure was the
binding constraint and the export failed with the unnamed ready timeout. So the preflight **warns
and does not block**, and `result=ready` with `exporter_memory_ok=no` or `image_vm_memory_ok=no`
means "this may work, and if it does not, here is why". From v1.16.2 the export helper's failure
names its figure, and a lower `SMOLVM_EXPORT_HELPER_MEMORY_MIB` is the fix; the image pull VM has
no such setting.

## Traps

Full detail with the evidence in `references/traps.md`. The ones that cost the most:

- **`--output` names the stub, not the sidecar.** Passing `--output foo.smolmachine` fails; the
  scripts refuse it before the CLI does.
- **"One file" needs `--single-file`, and the default is two.** By default `pack create` writes the
  stub plus a `.smolmachine` sidecar and the CLI says `Note: Keep the .smolmachine file alongside
  the binary`; the stub on its own prints smolvm's usage and exits. `--single-file` writes one
  executable with no sidecar, and its own help warns it `may have issues with macOS notarization`.
- **The stub takes a subcommand, and a bare `--` is rejected** with a tip that does not mention
  `run`. The working form is `./from-vm run -- sh -c '...'`.
- **`pack run` takes `--sidecar <PATH>`, not a positional path**, and getting it wrong reports
  that your sidecar is not an executable in `$PATH`.
- **Reported sizes understate the stub on disk**, by about 8.4 MB on Linux aarch64 and about
  10 MB on macOS arm64 on v1.14.6, 10.4 MB on macOS on v1.22.2: `pack create` prints its sizes,
  then signs the stub on macOS, then appends the compressed runtime libraries to it. The
  `Assets:` figure is accurate to a few KB.
- **A branched machine packs from v1.16.1, and carries both states**; v1.14.6 refused it at export.
  Start the source `--branchable`, `machine branch --from <src> --name <child>`, write a marker in the child, stop
  it, `pack create --from-vm <child>`, and the artifact prints the source's `BASE_STATE` and the
  child's `CHILD_ONLY`. The branch must be stopped before it will pack.
- **Branchability is decided at `machine start`, not at `create`.** `machine branch` against a
  machine started without it refuses with `was not started as branchable, so it has no
  copy-on-write memory to branch from ... branchability is decided at start time and cannot be
  turned on for an already-running machine`, and `machine create --branchable` is not a flag.
- **A checkpoint restore packs and carries its rootfs**, and the restore path is
  `machine create --from`. There is no `machine restore` subcommand. **On macOS before v1.20.0
  taking the checkpoint needs `--branchable`**, and the error, `guest RAM has no file-backed
  regions`, names neither the flag nor the precondition. From v1.20.0 a checkpoint file does not
  need it and a `--store` capture still does; `references/traps.md` has the releases. Linux
  aarch64 took one without it on v1.18.2. A machine created from a pack can be checkpointed from
  v1.18.0, and `create --from` restores the newest generation a checkpoint carries; `--at ~N` picks an earlier
  one, which `branch-and-checkpoint` covers.
- **On Linux, `SMOLVM_DATA_DIR` moves where the agent rootfs is looked up and the installer does
  not write it there**, so an isolated data root needs the rootfs copied in before the first boot.

## Security defaults, and why they are the defaults

- **An artifact is a filesystem you are handing to someone else.** Whatever was in the source
  machine's rootfs is in the sidecar, including anything a provisioning step left in a shell
  history, a cache, or a file under `/root`. The marker this packet writes is deliberately inert;
  treat anything else you put in the source as published.
- **Packing does not narrow what the artifact may do.** The recorded entrypoint, command,
  environment and network setting come from the source, so a machine created with `--net`
  produces an artifact that expects a network. Decide that on the source, not afterwards. CPUs and
  memory do not come from the source: they are `pack create --cpus` and `--mem`, else the
  Smolfile, else 4 and 8192 MiB.
- **The scripts pack only a machine they created**, named under the `smolskill-` prefix and
  recorded in a state file, and cleanup deletes only those and, through `--cascade`, any machine
  branched from one of them, whatever its name. Any other machine you or another session made by
  hand is never exported and never deleted.
- **`pack run` takes the forked boot path.** From v1.20.2 Ctrl-C or a kill of the CLI takes its VM
  with it: on macOS arm64 on v1.22.2 both processes of a packed `run` were gone 2 s after `SIGINT`
  and after `SIGKILL`. Before v1.20.2 a cancelled run left a VM the CLI could not see, and
  `cleanup.sh` is the way to stop one there; its process scan catches both VM shapes.
- **Nothing here escalates privilege**, edits smolvm configuration or touches `~/.smolvm`.

## Platform arms

- **macOS arm64**: verified on v1.22.2, including the SSH agent forwarding, a branched source, and
  a pack of a restored machine on v1.18.2. An extra `Signing binary with hypervisor entitlements`
  step runs here that does not on Linux.
- **Linux aarch64**: verified on v1.14.6. Not run on v1.18.2 or v1.22.2: `pack create --image`
  failed with `agent did not become ready within 30 seconds`, with or without `--mem 1024`,
  because the pull helper does not take `--mem`, and the golden machine's start failed the same
  way. That host could not boot guests above 2048 MiB in time, which the `install` packet's traps
  record. The preflight on v1.18.2 said `exporter_memory_ok=yes` there with 10386 MiB free: free
  memory was not what failed, so read the memory lines as hints about the helper VMs only.
- **Linux x86_64**: verified in the material behind this packet on v1.14.6, including the branched
  and restored cases. Not re-run here.
- **Windows x86_64**: `references/windows.md`. **On v1.22.2 an artifact is created and cannot
  be run there**, re-run on 2026-10-03 on Windows 11 Home build 10.0.26200 UBR 9457: both paths pack, and running any artifact,
  through its stub, `pack run --sidecar` or `machine create --from`, fails extracting its first
  layer with `os error 123`. v1.16.1 and v1.14.6 run the same pack on the same host; v1.18.2 and
  every later release tried fail. On v1.14.6 both paths worked end to end, with the marker read
  back out of the artifact. The stub is written without `.exe` and will not run until it and its
  sidecar are renamed.

**Both hosts run here produce `linux/arm64` artifacts**, so two hosts is two hosts and not two
artifact architectures. The `linux/amd64` side rests on the x86_64 run above.

## Eval prompts, and what they produced

Run 2026-09-11 PT against v1.14.6 from the published release, on macOS 26.6.2 arm64 and Lima
`linux-kvm` (Ubuntu 24.04 aarch64). Output is verbatim.

**1. "Ship this provisioned machine to another host as one file."**

Both hosts, through `pack-machine.sh` then `verify-pack.sh`:

```
source_marker=PACKED_STATE_PRESENT
result=packed

machine_pack_carried_rootfs=ok (PACKED_STATE_PRESENT)
machine_pack_is_a_vm=ok (Linux)
result=artifacts_good
```

macOS produced a 31572 KB sidecar in 3 s, Linux aarch64 a 31491 KB sidecar in 32 s.

**2. "The artifact runs fine but the thing I installed is not in it."**

That is the failure this packet is shaped against, and the answer is that running proves nothing.
`verify-pack.sh` asserts the marker rather than the boot, and `pack-machine.sh` refuses to export
at all if the marker is not on the source first:

```
result=FAILED the source does not carry the marker, so packing it would produce an empty artifact
```

The image pack is the control: it runs and does not carry the machine's state. State written
under `/workspace` needs `--include-workspace`.

**3. "`pack create --from-vm` fails with `agent did not become ready within 30 seconds` and says
nothing else."**

On v1.14.6 the preflight of that date was the only place that failure was named:

```
exporter_memory_mib=8192
free_memory_mib=4990
exporter_memory_ok=no
note=free memory is below the exporter's fixed 8192 MiB. If pack create --from-vm fails with
'agent did not become ready within 30 seconds', that is this, and the message will not mention
memory. Packing from an image starts no exporter and is unaffected.
```

On the hosts here the export then **succeeded anyway**, on the Mac reporting 4990 MiB, which is
why that line warns rather than blocks.

That is the v1.14.6 output, when the export helper was fixed at 8192 MiB. From v1.16.2 the
failure names the figure it asked for and `SMOLVM_EXPORT_HELPER_MEMORY_MIB`, and
`exporter_memory_mib` is what the binary will ask for, 4096 or less. The recorded note's last
sentence was never right: `pack create --image` boots its own 8192 MiB VM on every release here.

## Re-verified on v1.22.2

Run 2026-10-03 PT against v1.22.2 from the published release, checksum checked, under an isolated
`HOME` on macOS 27.0.1 arm64, twice, the second time from a fresh `HOME`. On Lima `linux-kvm`
(Ubuntu 24.04 aarch64) on 2026-10-03 guests above 2048 MiB timed out.

macOS: `result=artifacts_good (2 of 2 artifacts)` with `machine_pack_carried_rootfs=ok
(PACKED_STATE_PRESENT)`, the stub understated by 10657 KB, a branched machine's artifact printing
`BASE_STATE` and `CHILD_ONLY`, a checkpoint of a machine started without `--branchable`, and the
artifact's `run --ssh-agent` listing the host key's fingerprint. `SIGINT` and `SIGKILL` to a packed
`run` ended both its processes within 2 s. Docker Hub's anonymous pull limit stopped the first
verify run's image pack with `TOOMANYREQUESTS`; it passed on the re-run. The one-file route by
hand: `pack create --from-vm --single-file` wrote one 62890688-byte file, and `verify-pack.sh
--machine ... --marker-path` gave `image_pack=skipped` and `result=artifacts_good (1 of 2
artifacts)`.

Linux aarch64: not run. A default-size source machine and the image pack's pull VM both need
8192 MiB, and both timed out; the export helper was never reached.

## What was not run

- **Cross-platform rehydration**, except for one pair. An arm64 stub built on macOS was carried
  to x86_64 Windows on 2026-09-11 and **the OS loader refuses it before any smolvm code runs**:
  the stub runs only on the platform it was built on. `smolvm pack run --sidecar` refuses a
  sidecar built on another platform, with `this artifact was built for ... but the current
  platform is ...`. Nothing here ran a sidecar on another host of the same architecture.
- **`pack push`, `pack pull` and `pack inspect` against a registry.** Nothing here touched a
  registry.
- **Windows through these scripts.** `scripts/*.sh` are bash and do not run there; the
  Windows runs issued the CLI by hand. `references/windows.md` has them.
- **The branched and restored sources on Linux aarch64.** The restored source was run on macOS on
  v1.18.2 and the branched one on v1.22.2; both are answered on Linux
  x86_64 in the material behind this packet.
- **SSH agent forwarding on Linux.** Measured on macOS only.
- **Linux aarch64 on v1.18.2 and v1.22.2**, as above.

## Related packets

- `dev-env` for producing the machine that gets packed, and for the `init`-runs-once semantics
  its provisioning depends on.
- `install` for the boot this assumes, and `teardown` for the wider cleanup.
