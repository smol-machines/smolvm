---
name: pack
description: Turns an image, or a machine already provisioned, into a single self-contained artifact that runs on another compatible host. Use when shipping a prepared environment as one file, when a packed artifact runs but the state installed into it is missing, when pack create --from-vm fails with a ready timeout that names nothing, when an export is refused because the machine is a fork clone, or when deciding whether to pack from an image or from a machine. Do not use it to keep a machine you re-enter, which is the dev-env packet, or to run untrusted code, which is the sandbox packet.
---

# Packing a machine into a portable artifact

Verified on **smolvm v1.14.6** on macOS arm64 and Linux aarch64, 2026-09-11. Done means the
artifact runs a command in a real VM and, for a machine pack, **the state you installed is still
inside it**.

**The assertion that matters is a value, not a boot.** A pack that lost its rootfs still boots,
still prints a guest kernel and still exits zero. The only thing that separates a good artifact
from an empty one is a marker written into the source machine before packing and read back out of
the artifact afterwards, which is what `pack-machine.sh` and `verify-pack.sh` do between them.

## Procedure

**1. Preflight.** Read-only: starts no VM, packs nothing.

```bash
scripts/preflight.sh
```

The line to read is `exporter_memory_ok`. `pack create --from-vm` starts an exporter VM whose
memory is **hardcoded to 8192 MiB** with no flag and no environment variable, and on a host that
cannot give it that the export fails as `agent did not become ready within 30 seconds`, which
mentions neither memory nor the exporter. **This preflight is the only place that failure has a
name.** It is a warning and not a gate, because the figure is a cap rather than a reservation: see
"What the memory line does and does not promise".

**2. Pack from an image**, when you want a runnable artifact of a stock image.

```bash
scripts/pack-image.sh                       # alpine, ./from-image
scripts/pack-image.sh python:3.12-alpine ./mypack
```

This path starts no exporter, so the memory line does not apply to it. **If you pass a custom
output, pass it to the verify step too** (`verify-pack.sh --image ./mypack`), or that step finds
nothing at its defaults and tells you so rather than passing.

**3. Pack from a machine you provisioned**, when the point is the state in it.

```bash
scripts/pack-machine.sh                     # smolskill-golden, ./from-vm
```

It creates the machine with a workload that stays up, waits for a value from it, writes a marker,
**asserts the marker on the source**, stops the machine and exports it. The source assertion is
not ceremony: packing a machine whose provisioning silently failed produces an artifact that runs
perfectly and contains nothing, and nothing downstream will tell you.

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

It prunes each recorded machine while it still exists, deletes it, removes both stubs and their
sidecars, and runs `pack prune`. **`smolvm machine prune` with no argument does not run on this
release**; the form is `--name <NAME>`.

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
is not the exporter's, which nothing can set.

## What the memory line does and does not promise

The exporter's 8192 MiB is a **cap, not a reservation**, so a host reporting less available memory
can still export. Measured on this release: the export succeeded on a Mac whose preflight reported
`free_memory_mib=4990`, well under the figure, and it is the binding constraint on a small Linux
box where it fails with the unnamed ready timeout. So the preflight **warns and does not block**,
and `result=ready` with `exporter_memory_ok=no` means "this may work, and if it does not, here is
why".

## Traps

Full detail with the evidence in `references/traps.md`. The ones that cost the most:

- **`--output` names the stub, not the sidecar.** Passing `--output foo.smolmachine` fails; the
  scripts refuse it before the CLI does.
- **The stub takes a subcommand, and a bare `--` is rejected** with a tip that does not mention
  `run`. The working form is `./from-vm run -- sh -c '...'`.
- **`pack run` takes `--sidecar <PATH>`, not a positional path**, and getting it wrong reports
  that your sidecar is not an executable in `$PATH`.
- **Reported sizes understate the stub on disk**, by about 8.4 MB on Linux aarch64 and about
  10 MB on macOS arm64, where an extra signing step runs. The sidecar figure is accurate.
- **A fork clone is refused at export**, by design, with a message naming both remedies: pack the
  golden it came from, or recreate the state in a machine that was never branched.
- **A checkpoint restore packs and carries its rootfs**, and the restore path is
  `machine create --from`. There is no `machine restore` subcommand.
- **On Linux, `SMOLVM_DATA_DIR` moves where the agent rootfs is looked up and the installer does
  not write it there**, so an isolated data root needs the rootfs copied in before the first boot.

## Security defaults, and why they are the defaults

- **An artifact is a filesystem you are handing to someone else.** Whatever was in the source
  machine's rootfs is in the sidecar, including anything a provisioning step left in a shell
  history, a cache, or a file under `/root`. The marker this packet writes is deliberately inert;
  treat anything else you put in the source as published.
- **Packing does not narrow what the artifact may do.** The recorded entrypoint, network setting
  and memory come from the source, so a machine created with `--net` produces an artifact that
  expects a network. Decide that on the source, not afterwards.
- **The scripts pack only a machine they created**, named under the `smolskill-` prefix and
  recorded in a state file, and cleanup deletes only those. A machine you or another session made
  by hand is never exported and never deleted.
- **`pack run` takes the forked boot path**, so a cancelled run leaves a VM the CLI cannot see.
  `cleanup.sh` is the way to stop one, and its process scan catches both VM shapes. Ctrl-C is not.
- **Nothing here escalates privilege**, edits smolvm configuration or touches `~/.smolvm`.

## Platform arms

- **macOS arm64**: verified on v1.14.6. An extra `Signing binary with hypervisor entitlements`
  step runs here that does not on Linux.
- **Linux aarch64**: verified on v1.14.6.
- **Linux x86_64**: verified in the material behind this packet on v1.14.6, including the branched
  and restored cases. Not re-run here.

**Both hosts run here produce `linux/arm64` artifacts**, so two hosts is two hosts and not two
artifact architectures. The `linux/amd64` side rests on the x86_64 run above.
- **Windows x86_64**: `references/windows.md`, **re-run on 2026-09-11 against v1.14.6** on
  Windows 11 Home build 10.0.26200.0 UBR 9445. Both paths work: the image pack, and `--from-vm`
  for the first time there, with the marker read back out of the artifact. The stub is written
  without `.exe` and will not run until it and its sidecar are renamed.

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

The image pack is the control: it runs and does not carry the machine's state.

**3. "`pack create --from-vm` fails with `agent did not become ready within 30 seconds` and says
nothing else."**

Run the preflight, which is the only place that failure is named:

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

## What was not run

- **Cross-platform rehydration**, except for one pair. An arm64 stub built on macOS was carried to
  x86_64 Windows on 2026-09-11 and **the OS loader refuses it before any smolvm code runs**, so an
  artifact has to be built on the platform it will run on. Nothing tests the reverse direction, or
  two hosts of the same architecture on different operating systems.
- **`pack push`, `pack pull` and `pack inspect` against a registry.** Nothing here touched a
  registry.
- **Windows through these scripts.** `scripts/*.sh` are POSIX shell and do not run there; the
  2026-09-11 v1.14.6 run on Windows issued the CLI by hand. `references/windows.md` has it.
- **The branched and restored sources on these two hosts.** Both are answered on Linux x86_64 in
  the material behind this packet and are written up in `references/traps.md` as behaviour; they
  were not re-run on macOS or aarch64.

## Related packets

- `dev-env` for producing the machine that gets packed, and for the `init`-runs-once semantics
  its provisioning depends on.
- `install` for the boot this assumes, and `teardown` for the wider cleanup.
