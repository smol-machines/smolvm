# Packing on Windows

## Contents

- What was verified
- `--from-vm` works here, and the marker proves it
- The stub is written without `.exe`
- An artifact built for another architecture is refused by Windows, not by smolvm
- The template requirement the caveats describe is already satisfied
- The trap that makes `pack run` look broken
- What was never run here

**Re-run on 2026-09-11 against smolvm v1.14.6** on Windows 11 Home build 10.0.26200.0 UBR 9445
x86_64 (Intel Core Ultra 9 185H, 31.6 GB), in an elevated session. `scripts/*.sh` are POSIX shell
and do not run there, so every command below was issued by hand from PowerShell.

The image path and the sizes in the next section are from the earlier v1.14.2 run on the same host
and were not measured again. The three sections after it are the v1.14.6 run.

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

**First time `pack create --from-vm` has been run on Windows.** A marker was written inside the
source machine, the machine was packed, and the marker was read back out of the artifact:

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

Reading the marker back out is the assertion, not the boot. The exporter VM and its fixed memory
behave as `references/traps.md` describes; nothing on this host hit that ceiling.

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
this pair: an artifact has to be built on the platform it will run on.

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
