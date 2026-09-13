# Pack traps

## Contents

- `--output` names the stub, not the sidecar
- The stub takes a subcommand, and a bare `--` is rejected
- `pack run` takes `--sidecar`, not a positional path
- The exporter's 8192 MiB, and what the failure looks like
- Verify the state, not the boot
- Reported sizes understate the stub on disk
- A fork clone is refused at export
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

## The exporter's 8192 MiB, and what the failure looks like

`pack create --from-vm` starts an exporter VM whose memory is **hardcoded to 8192 MiB**:
`src/pack_export.rs:345` at `3412bd26`, `memory_mib: 8192`. A second exporter VM at `:914` is
hardcoded to `cpus: 2, memory_mib: 2048`. A grep of that file for `env::var`, any `SMOLVM_*MEM`
and `--mem` returns nothing, so **neither is overridable**.

`pack create --mem` sets the **packed artifact's** runtime memory, not the exporter's. The two are
easy to confuse because `--info` reports the artifact's figure and it is also 8192 by default.

On a host that cannot give the exporter that much, the export fails as:

```
agent did not become ready within 30 seconds
```

which names neither memory nor the exporter. `scripts/preflight.sh` is the only place it gets a
name.

**It is a cap and not a reservation, so the figure does not decide the outcome.** Measured on
v1.14.6: the export **succeeded** on a Mac whose preflight reported `free_memory_mib=4990`, and
the same trap was the binding constraint on a 10.9 GiB Linux box in the material behind this
packet. That is why the preflight warns rather than blocks. The citation has drifted twice, from
`:299` to `:311` at v1.14.2 to `:345` now, so check the line before quoting it.

## Verify the state, not the boot

**A pack that lost its rootfs still boots, still prints a guest kernel and still exits zero.**
Packing a machine whose provisioning silently failed produces an artifact that runs perfectly and
contains nothing. That happened in the runbook session behind this packet: a provisioning `exec`
had failed unnoticed and the resulting pack reported `MISSING` for both markers.

The shape that makes it impossible is the one these scripts use: write a marker into the source,
**assert it on the source before packing**, and read it back out of the artifact afterwards.
`pack-machine.sh` exits non-zero rather than exporting a machine that does not carry its marker.

## Reported sizes understate the stub on disk

`pack create` reports a stub smaller than the file it wrote, so its `total:` understates by the
same amount. Measured on v1.14.6:

| host | reported | on disk | understated by |
|---|---|---|---|
| Linux aarch64 | 30737 KB | 39195 KB | 8458 KB |
| macOS arm64 | 29643 KB | 39883 KB | 10240 KB |

The macOS gap is larger because an extra `Signing binary with hypervisor entitlements` step runs
there. The sidecar figures are accurate on both. **Do not size a disk budget or an upload from the
reported total.**

## A fork clone is refused at export

Packing a branched machine is refused, by design, and the message names both remedies:

```
machine 'child' is a fork clone of 'src'; its copy-on-write disks cannot be exported
directly. Export the golden instead, or recreate the state in a non-clone machine and
export that.
```

The child itself carries the source's state and runs normally; it is only the export that
refuses. **So a branched machine is packed through its golden.** No artifact is produced, so there
is nothing to verify afterwards.

## A checkpoint restore packs, and the restore path is not `machine restore`

A machine restored from a checkpoint packs, runs, and carries its rootfs. This is the case
[#1174](https://github.com/smol-machines/smolvm/pull/1174) changed, shipped in v1.14.3.

There is **no `machine restore` subcommand**, which is the obvious guess and gives
`unrecognized subcommand`. The restore path is `machine create --from <PATH>`, the same flag that
takes a `.smolmachine`, documented as "Create from a `.smolmachine` pack or restore a
`.smolcheckpoint`".

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
wide, while `--name` is documented as "Machine to prune". `smolvm pack prune`, which clears cached
pack extractions, does take no required argument. Any cleanup line that says `smolvm machine
prune` bare is wrong on this release.

**And the machine form starts the machine to do its work**, observed on Linux aarch64:

```
Starting machine...
Removing unreferenced layers...
No unreferenced layers to remove.
```

So it is worth running while the machine still exists and before deleting it, which is the order
`scripts/cleanup.sh` uses. Run after the delete it is a silent no-op.
