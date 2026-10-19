# Live resize

`machine resize` grows a running machine's CPUs, RAM or disks without
rebooting it. Processes, open connections and RAM-only data stay as they are;
the guest sees the new CPUs, memory and filesystem space at once.

```sh
smolvm machine resize --name worker --cpus 8
smolvm machine resize --name worker --mem 16384           # MiB
smolvm machine resize --name worker --storage 100         # GiB
smolvm machine resize --name worker --cpus 8 --mem 16384  # several at once
```

Sizes are absolute targets, not increments. Several resources in one command
are checked together before anything changes, then applied RAM first, CPUs,
then disks. If a later step fails, the command says which earlier ones already
took effect.

## What can change, and where

| Resource | Grow while running | Shrink while running |
|---|---|---|
| CPUs | Linux x86_64, macOS Apple Silicon | Linux x86_64, with a compatible runtime and agent |
| RAM | Linux x86_64 and aarch64, macOS Apple Silicon | no |
| Storage and overlay disks | yes, with a runtime and agent that support online growth | no |

KVM on arm64 cannot add vCPUs to a running guest, so a machine on arm64 Linux
keeps its CPU count until it is stopped and started.

On Linux, RAM growth also needs the VM in a cgroup smolvm manages, so it can
raise the VM's memory limit first: a machine started by `smolvm serve` running
as a systemd service (each VM gets its own scope) or with a delegated cgroup
root. A machine started from the CLI, or under `serve` in a desktop session,
refuses with `live RAM growth currently requires a runtime-managed VM memory
scope` and changes nothing; stop it and start it with more `--mem` instead.
CPU and disk growth have no such requirement.

RAM growth first checks that the host has headroom for it and refuses before
changing anything if it does not. Requests that would shrink RAM or a disk are
refused without reducing capacity.

A disk with dependent live branches cannot grow: the branches use it as their
copy-on-write base.

## Stopped machines

`machine resize` also grows a stopped machine's disks; the filesystem expands
on the next boot. CPU and RAM settings of a stopped machine are changed with
`machine update --cpus N --mem MiB`, and take effect on the next start.

## Safety

Each live resize is journaled before it touches the machine and is tied to the
exact VM process it observed. If that process exits or is replaced, the resize
is refused rather than applied to a different boot. An interrupted resize is
finished or reconciled the next time the API server runs. Each one is recorded
as a `resize` event in the [usage journal](usage-journal.md).

## API and SDKs

The node API exposes `POST /api/v1/machines/{name}/resize` with `cpus`,
`memoryMb`, `storageGb` and `overlayGb`. A running machine takes one kind of
resource per request. Pass the machine's reported `runtime` back as
`expectedRuntime` to refuse the resize if the machine was restarted in between,
and an `operationId` (which requires `expectedRuntime`) to retry the same
request safely. The embedded SDKs resize through the same engine.
