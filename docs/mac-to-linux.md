# Moving a running machine from a Mac to Linux

A checkpoint taken on an Apple silicon Mac resumes on an arm64 Linux host,
processes and all. Start a machine on your laptop, checkpoint it, copy the file
to a Linux server, and it keeps running there from the same instruction.

```sh
# On the Mac
smolvm machine create --name agent --image alpine --net
smolvm machine start --name agent --branchable
smolvm machine checkpoint --name agent --output agent.checkpoint

# Copy agent.checkpoint to an arm64 Linux host, then on that host
smolvm machine create --name agent --from agent.checkpoint
smolvm machine start --name agent
```

The restored machine keeps its memory, running processes, open listeners,
published ports and disks. Once it runs on Linux it is an ordinary Linux
machine: it can be checkpointed, restored and branched there like any other.

## Requirements

| Requirement | Why |
|---|---|
| Source is an arm64 Mac, destination is arm64 Linux with KVM | Running state cannot change CPU architecture. |
| The machine was started by a smolvm that supports the move | Older runtimes do not record the guest clock or the virtual board. smolvm refuses those checkpoints with "capture it again with a newer smolvm". |
| The Linux CPU provides every feature the guest was given | A Mac guest's features are a subset of current arm64 server CPUs, including Graviton and Axion. A missing feature is named in the error. |
| At most 16 vCPUs, no GPU, no host mounts | The same limits as any portable checkpoint, plus the vCPU numbering both hypervisors share. |

## What changes after the move

**The clock source.** Apple silicon's system counter runs at 24 MHz and most
arm64 servers run theirs at 1 GHz. The guest kernel notices the new rate on its
first timer interrupt after the restore and keeps every clock correct. Programs
that call `clock_gettime()` keep working, but the call goes through the kernel
instead of the vDSO until the machine next boots, which makes it a little slower.

**Pointer authentication.** Apple silicon signs pointers with an algorithm no
other CPU implements. Machines started on a Mac therefore boot with pointer
authentication turned off, so their checkpoints can move. The VM boundary is
still the isolation boundary; this removes one hardening layer inside the guest.

**CPU hot-add.** KVM on arm64 cannot add vCPUs to a running guest, so a machine
moved from a Mac keeps the vCPUs it has until it is stopped and started again.

## Not supported yet

- Moving a machine from Linux to a Mac.
- Moving between CPU architectures (arm64 and x86_64), in either direction.
