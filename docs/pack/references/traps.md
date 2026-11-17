# Pack traps

## Contents

- `--output` names the stub, not the sidecar
- The stub takes a subcommand, and a bare `--` is rejected
- `pack run` takes `--sidecar`, not a positional path
- The helper VMs' memory, by release, and what the failure looks like
- Verify the state, not the boot
- Reported sizes understate the stub on disk
- A branched machine packs on v1.16.1, and was refused on v1.14.6
- A checkpoint restore packs, and the restore path is not `machine restore`
- An isolated data root on Linux does not carry the agent rootfs
- `smolvm machine prune` needs a machine, and it starts one
- On Windows the stub is written without `.exe`

## `--output` names the stub, not the sidecar

Passing `--output foo.smolmachine` fails immediately, and the error is good: it says the sidecar
is created automatically as `<output>.smolmachine` and to pass `--output ./foo`. Read it rather
than guessing. `scripts/pack-image.sh` and `scripts/pack-machine.sh` refuse the `.smolmachine`
form before the CLI sees it.

## On Windows the stub is written without `.exe`

`pack create -o pimg` on Windows writes `pimg` and `pimg.smolmachine`, and PowerShell refuses to
execute the extensionless stub:

```
ERROR: Cannot run a document in the middle of a pipeline: C:\...\pimg.
```

Rename it to `p.exe` with `p.exe.smolmachine` beside it and it runs, printing `PACK_IMG_OK` from
the packaged entrypoint. The sidecar has to be renamed too, because the stub looks for its own
name plus `.smolmachine`. Observed on v1.14.6; `references/windows.md` has the run.

## The stub takes a subcommand, and a bare `--` is rejected

```
$ ./from-vm -- sh -c 'echo hi'
tip: subcommand 'sh' exists; to use it, remove the '--' before it
```

The working forms are `./from-vm run -- sh -c '...'` and `./from-vm` alone, which executes the
packaged entrypoint. The tip does not mention `run`, which is the part that costs the time.

## `pack run` takes `--sidecar`, not a positional path

```
$ smolvm pack run ./x.smolmachine -- cmd
executable file `./x.smolmachine` not found in $PATH
```

The path was consumed as the command to run. Nothing in the message points at `--sidecar`.

## The helper VMs' memory, by release, and what the failure looks like

`pack create --from-vm` boots an export helper VM. **Through v1.16.1** its memory was fixed,
`memory_mib: 8192` in `src/pack_export.rs` (`:345` at v1.14.6, `:384` at v1.16.1), with no flag
and no variable, and on a host that could not give it that much the export failed as

```
agent did not become ready within 30 seconds
```

which named neither memory nor the helper.

**From v1.16.2** (#1312) it asks for 4096 MiB. On Linux it asks for half of the available memory
instead when that is less, and never under 1024 MiB; macOS and Windows ask for 4096.
`SMOLVM_EXPORT_HELPER_MEMORY_MIB=<MiB>` sets it, `SMOLVM_EXPORT_HELPER_STORAGE_GIB=<GiB>` sets its
disk, and a helper that cannot start ends with `The export helper asked for N MiB of memory and a
G GiB disk. If this host cannot seat that, set SMOLVM_EXPORT_HELPER_MEMORY_MIB=<MiB> and/or
SMOLVM_EXPORT_HELPER_STORAGE_GIB=<GiB> and retry.` (`src/pack_export.rs:289-335` and `:514-522`
at v1.22.2). A bare machine, one with no image, is flattened by a separate helper fixed at 2 vCPUs
and 2048 MiB.

**`pack create --image` is the path with a fixed 8192 MiB VM** on every release here: it pulls
the image in a temporary VM of 4 vCPUs and 8192 MiB (`src/cli/pack.rs:730-742` at v1.22.2), which
no flag or variable changes, and a host that cannot seat it fails with the same bare ready
timeout.

`pack create --mem` sets the **packed artifact's** runtime memory, not either helper's. The two
are easy to confuse because `--info` reports the artifact's figure and it is also 8192 by default.

**It is a cap and not a reservation, so the figure does not decide the outcome.** Measured on
v1.14.6: the export **succeeded** on a Mac whose preflight reported `free_memory_mib=4990`, and
the fixed figure was the binding constraint on a 10.9 GiB Linux host in the material behind this
packet. That is why the preflight warns rather than blocks.

## Verify the state, not the boot

**A pack that lost its rootfs still boots, still prints a guest kernel and still exits zero.**
Packing a machine whose provisioning silently failed produces an artifact that runs perfectly and
contains nothing. In the runs behind this packet a provisioning `exec` once failed unnoticed,
and the resulting pack reported `MISSING` for both markers.

The shape that makes it impossible is the one these scripts use: write a marker into the source,
**assert it on the source before packing**, and read it back out of the artifact afterwards.
`pack-machine.sh` exits non-zero rather than exporting a machine that does not carry its marker.

## Reported sizes understate the stub on disk

`pack create` prints its sizes before it has finished the stub. In the default two-file mode the
`stub:` figure is the smolvm binary it copied, and `total:` is that plus the sidecar. After
printing, it signs the stub on macOS (`Signing binary with hypervisor entitlements...`) and then
appends the runtime libraries to it, compressed, with a 32-byte footer: `libkrun` and `libkrunfw`,
plus the GPU rendering libraries when the install has them (`libvirglrenderer`, `libMoltenVK` and
`libepoxy` on macOS; `libvirglrenderer`, `libepoxy` and `virgl_render_server` on Linux). That
appended block is what the report leaves out. Measured on v1.14.6:

| host | reported | on disk | understated by |
|---|---|---|---|
| Linux aarch64 | 30737 KB | 39195 KB | 8458 KB |
| macOS arm64 | 29643 KB | 39883 KB | 10240 KB |

On macOS arm64 on v1.22.2 the gap was 10657 KB. `Assets:` is the compressed payload, and the
sidecar file adds only its manifest and a 64-byte footer, so that figure is accurate to a few KB.
With `--single-file` the libraries go inside the one file before the sizes are printed, and only
the macOS signature is added afterwards. **Do not size a disk budget or an upload from the reported
total.**

## A branched machine packs on v1.16.1, and was refused on v1.14.6

**#1251 closed this.** Verified on macOS arm64 on v1.16.1, 2026-09-15: a child branched from a
source started `--branchable`, given its own marker and then stopped, packs, and the artifact
prints the source's `BASE_STATE` and the child's `CHILD_ONLY`. A running branch is refused with
`VM 'bchild' is running. Stop it first`. Branchability is decided at `machine start --branchable`,
not at create.

Everything below is the **v1.14.6** behaviour, kept because a host on an older release still meets
it. Packing a branched machine was refused, by design, and the message named both remedies:

```
machine 'child' is a fork clone of 'src'; its copy-on-write disks cannot be exported
directly. Export the golden instead, or recreate the state in a non-clone machine and
export that.
```

The child itself carries the source's state and runs normally; it is only the export that
refuses. **So a branched machine is packed through its golden.** No artifact is produced, so there
is nothing to verify afterwards.

## A checkpoint restore packs, and the restore path is not `machine restore`

**First you have to be able to take the checkpoint, and on macOS before v1.20.0 that needs
`--branchable`.**
Verified on macOS arm64 on v1.16.1, 2026-09-15: `machine checkpoint` against a machine started
without it fails with

```
Error: agent operation failed: checkpoint machine: libkrun save failed: ERR EIO capture VM:
VM snapshot/restore failed: retain COW guest-memory generation: guest RAM has no file-backed
regions
```

which names neither the flag nor the precondition. Started with
`machine start --name <n> --branchable`, the same command wrote 46 MiB in 2.554s with a 0.292s
source pause. Branchability is decided at start and cannot be turned on afterwards. **The same on
v1.18.2 on macOS, 2026-09-24**, with the same message. On Linux aarch64 v1.18.2 took the checkpoint
of a machine started without the flag: `Checkpointed ... (55 MiB written, 1.781s total, 1.242s
source pause)`.

**v1.20.0 lifted it on macOS for a checkpoint file**, measured on 2026-10-03 with a 1024 MiB alpine
machine started without the flag on each release: v1.19.0 and v1.19.3 failed with the message above,
and v1.20.0, v1.20.2, v1.21.1, v1.22.0 and v1.22.2 each wrote one, for example
`Checkpointed 'nb' to ./c.smolcheckpoint (54 MiB written, 0.911s total, 0.300s source pause)` on
v1.20.0. **A stored checkpoint still needs the flag**: `--store` against the same kind of machine
on v1.22.2 fails with

```
Error: agent operation failed: checkpoint machine: libkrun save failed: ERR ENOTSUP VM
snapshot/restore failed: retain COW guest-memory generation: deferred durable save requires
file-backed guest RAM
```

A machine **created from a pack** checkpoints from v1.18.0 (#1361), and its restore reattaches the
pack's layers: on macOS on v1.18.2 a machine created from `from-vm.smolmachine`, checkpointed,
restored and packed again gave an artifact carrying the marker written after the pack.

A machine restored from a checkpoint packs, runs, and carries its rootfs. This is the case
[#1174](https://github.com/smol-machines/smolvm/pull/1174) changed, shipped in v1.14.3.

There is **no `machine restore` subcommand**, which is the obvious guess and gives
`unrecognized subcommand`. The restore path is `machine create --from <PATH>`, the same flag that
takes a `.smolmachine`, documented as "Create from a `.smolmachine` pack or restore a
`.smolcheckpoint`". From v1.19.1 `machine checkpoint --help` names the file `.checkpoint` instead,
and its error for any other name is `output must end in .checkpoint`; v1.22.2 accepts both.

## An isolated data root on Linux does not carry the agent rootfs

`SMOLVM_DATA_DIR` relocates the whole data root **including where the agent rootfs is looked up**,
and the installer does not write it there. The first boot under an isolated root fails with:

```
agent rootfs not found: <data root>/.local/share/smolvm/agent-rootfs
```

which points at a missing file rather than at the variable that moved it. Copy the installer's
`agent-rootfs` in first:

```bash
mkdir -p "$SMOLVM_DATA_DIR/.local/share/smolvm"
cp -r "$HOME/.local/share/smolvm/agent-rootfs" "$SMOLVM_DATA_DIR/.local/share/smolvm/"
```

`scripts/preflight.sh` reports `data_root_rootfs=missing` when the variable is set and the rootfs
is not there.

## `smolvm machine prune` needs a machine, and it starts one

The bare form does not run on v1.14.6:

```
$ smolvm machine prune
Usage: smolvm machine prune --name <NAME>
```

Its own help describes "Remove unused images and layers to free disk space", which reads host
wide, while `--name` is documented as "Machine to prune". `smolvm pack prune`, which removes cached
pack extractions beyond the five most recently used, does take no required argument. Any cleanup
line that says `smolvm machine prune` bare is wrong on this release.

**And the machine form starts the machine to do its work**, observed on Linux aarch64:

```
Starting machine...
Removing unreferenced layers...
No unreferenced layers to remove.
```

So it is worth running while the machine still exists and before deleting it, which is the order
`scripts/cleanup.sh` uses. Run after the delete it is a silent no-op.
