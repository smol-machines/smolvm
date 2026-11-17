# Packing on Windows

## Contents

- On v1.22.2 an artifact cannot be run here
- What was verified
- `--from-vm` works here, and the marker proves it
- The stub is written without `.exe`
- An artifact built for another architecture is refused by Windows, not by smolvm
- The template requirement the caveats describe is already satisfied
- The trap that makes `pack run` look broken
- What was never run here

**Re-run on 2026-10-03 against smolvm v1.22.2**, where an artifact could not be run (the next
section). "What was verified" is from the earlier v1.14.2 run on the same host, and its image path
and sizes were not measured again. The three sections after it are the **2026-09-11 run against
v1.14.6** on Windows 11 Home build 10.0.26200.0 UBR 9445 x86_64 (Intel Core Ultra 9 185H,
31.6 GB), in an elevated session. `scripts/*.sh` are bash and do not run there, so every
command below was issued by hand from PowerShell.

## On v1.22.2 an artifact cannot be run here

Run on 2026-10-03 on Windows 11 Home build 10.0.26200 UBR 9457. `pack create` still works on both paths: `--from-vm` of a machine
holding a marker wrote `pk` (45.6 MB) and `pk.smolmachine` (17.7 MB) in 6.8 s, and an image pack
wrote its pair too. **Running either fails**, through the renamed stub, through
`pack run --sidecar` and through `machine create --from`, at the first layer:

```
extract assets: extracting C:\Users\<user>\AppData\Local\smolvm-pack\298779be\layers\48b0d0cc....tar
into ...\layers\48b0d0cc... failed, nothing was kept: The filename, directory name, or volume
label syntax is incorrect. (os error 123)
```

The same `pack create --image alpine` and `pack run --sidecar` on the same host on 2026-10-03,
with the pack cache emptied before each release:

| release | run |
|---|---|
| v1.14.6, v1.16.1 | `PACK_RUN_OK` |
| v1.18.2, v1.19.3, v1.20.2, v1.21.1, v1.22.2 | `os error 123` |

`alpine:3.19`, `alpine:3.20` and `busybox` fail the same way on v1.22.2, so it is not one image.
Until a release changes this, an artifact meant for a Windows host cannot be checked there; the
sections below record what worked on v1.14.6.

## What was verified

The image path works.

```powershell
& $exe pack create --image alpine --output "$dir\wpack"
& $exe pack run --sidecar "$dir\wpack.smolmachine" -- sh -c "echo PACK_RAN_OK"
& $exe pack run --sidecar "$dir\wpack.smolmachine" --info
```

Observed:

```
pack create  in 12.9s
Creating storage template...
Packed: ...\wpack (stub: 31615KB, total: 49851KB)
Assets: ...\wpack.smolmachine (18234KB compressed)

pack run     exitcode 0   PACK_RAN_OK
pack run --info            Platform: linux/amd64   Memory: 8192 MiB   Checksum: 1f7ced2a
```

## `--from-vm` works here, and the marker proves it

**The 2026-09-11 run on v1.14.6 was the first `pack create --from-vm` on Windows.** A marker was
written inside the source machine, the machine was packed, and the marker was read back out of the
artifact:

```
----- B. pack create --from-vm (never run on Windows before)
  Created machine: psrc
    out: Machine 'psrc' running (PID: 12908)
    FROMVM_MARKER_0911
    Stopped machine: psrc
  Assets: C:\...\pvm.smolmachine (18239KB compressed)
  artifacts: pvm, pvm.smolmachine
----- read the marker back out of the artifact
  FROMVM_MARKER_0911
```

Reading the marker back out is the assertion, not the boot. The export helper VM, fixed at 8192 MiB
on v1.14.6, behaves as `references/traps.md` describes; nothing on this host hit that ceiling.

## The stub is written without `.exe`

`pack create -o <name>` writes the stub with no extension, and PowerShell will not execute it:

```
  pimg   44354243
  pimg.smolmachine   18678054
```

```
ERROR: Cannot run a document in the middle of a pipeline: C:\...\pimg.
```

Rename the stub to `p.exe`, keeping `p.exe.smolmachine` beside it, and the same artifact runs:

```
PACK_IMG_OK
```

The sidecar has to be renamed with it: the stub looks for `<stub name>.smolmachine`. Still present
on v1.14.6.

## An artifact built for another architecture is refused by Windows, not by smolvm

An arm64 stub built on macOS with the v1.14.6 darwin release, carried to this x86_64 Windows host:

```
Program 'parm.exe' failed to run: The specified executable is not a valid application for this OS platform.
```

The stub is a macOS arm64 binary, so Windows refuses to load it before any smolvm code runs. **This
is a platform answer rather than a pack-format one**, and it is the cross-architecture answer for
this pair: the stub runs only on the platform it was built on.

## The template requirement the caveats describe is already satisfied

`AGENTS.md` says `pack create` on Windows "needs `storage-template.ext4` /
`overlay-template.ext4` beside `smolvm.exe` (Windows has no host `mkfs.ext4`)". **The release
ships both**, uncompressed at 536870912 bytes each, in the same folder as the exe, so the
requirement is met out of the box and needs no user action.

This is a real platform difference rather than a mistake in the caveat: the Unix releases ship
those templates as `.zst`, and Windows ships them expanded.

## The trap that makes `pack run` look broken

`pack run` returned **no output at all** under `Start-Process -RedirectStandardOutput`, which
reads as a silent failure. The same command through `cmd /c "... > out.txt 2>&1"` exits 0 and
prints `PACK_RAN_OK`.

**Do not conclude `pack run` is broken on Windows from an empty capture.** Check the invocation
first. This is the same captured-output shape that affects `machine start` there, which the
`install` packet's Windows page describes in full.

## What was never run here

- **An x86_64 Windows artifact carried to another host.** The pair that was tried is the reverse,
  above, and it is refused by the OS loader.
- **`pack push`, `pack pull` and `pack inspect`** against a registry.
