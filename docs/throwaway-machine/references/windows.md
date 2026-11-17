# Throwaway machines on Windows

## Contents

- What was verified
- On v1.22.2
- Why the offline shape is unavailable
- What a Windows run has to do instead
- The reaper on Windows

**Re-run on 2026-10-03 against smolvm v1.22.2** on Windows 11 Home build 10.0.26200 UBR 9457
x86_64, in an elevated session; the section "On v1.22.2" below has that run. The rest of this page
is the **2026-09-11 run against v1.14.6** on build 10.0.26200.0 UBR 9445, also elevated. The host mount, the artifact-out directory and the network-off
refusal all behaved as recorded below, and the bake still never completes. The transcripts below
are from the earlier v1.14.2 run except where a v1.14.6 line is quoted. `scripts/*.sh` are
bash and do not run here.

## What was verified

The read-only mount, the artifact-out directory and the network-off refusal all behave as on Unix.

```powershell
& $exe machine run --net --mem 2048 --image python:3.12-alpine `
    -v "$W\repo:/workspace:ro" -v "$W\out:/out" `
    -- sh -c 'python3 /workspace/calc.py > /out/result.txt; touch /workspace/EVIL 2>/dev/null && echo WS_WRITABLE || echo ws_blocked'
```

```
ws_blocked
host result.txt : 42
EVIL in repo    : False
```

The run took 5.8 s. Windows host paths work directly in `-v` (`C:\...\repo:/workspace:ro`),
including from a 237-character directory.

The same shape ran again on v1.14.6, asserting the mount with a marker of that run's own,
`SANDBOX_MOUNT_OK`, rather than a timing:

```
SANDBOX_MOUNT_OK
elapsed s : 9.7
```

A network-off run refuses to pull and prints the same hint as Unix, on v1.14.6 as before:

```
Error: fetching manifest docker.io/library/python:3.12-alpine: ... network is unreachable
Hint: networking is disabled. Add --net to enable image pulls:
  smolvm machine run --net --image python:3.12-alpine ...
```

## On v1.22.2

Run 2026-10-03 PT from the published zip.

- **The mount, the artifact directory and the network-off refusal held.** The command above
  printed `ws_blocked`, the host's `result.txt` read `42`, and there was no `EVIL` in the repo. A
  run without `--net` stopped at the pull with `dial udp 1.1.1.1:53: connect: network is
  unreachable` and the same hint. Windows on v1.22.2 has no image seed, so the image is pulled in
  the guest and a run without network cannot start.
- **The bake still never completes.** Four shapes, each capped at five minutes, all stalled on
  `Caching image <hash>` or `Baking init layer ...`: no mount and no `init`, a `:ro` mount, `--init
  true`, and both. Each left an `init-bake-<hash>-<pid>` machine listed as `running` at 8192 MiB,
  four at once until deleted.
- **A plain foreground `machine run` leaves its VM running when interrupted.** With a real Ctrl-C
  delivered to the CLI's console, and again with the CLI killed, the CLI exited and its `_boot-vm`
  was alive 10 s later, listed as `vm-<id> running (eph)`. `machine stop --name vm-<id>` ended it,
  and the entry stayed as `stopped (eph)` until `machine delete --name vm-<id> --force`.

## Why the offline shape is unavailable

**The `--oci-cache` bake never completes on Windows, still on v1.14.6.** It stalls at the same
line. Capped at ten minutes on the 2026-09-11 run and killed there:

```
Caching image 6e96a1a9683d8fb2 (one-time; reused on later runs)
  pulling image and running init...
```

Probed while hanging, the bake's helper VM is running and healthy: `PID 1 /run/smolvm/init
container-init` and nothing else, working egress, and 20.9 MB of pulled layers already on its
storage disk. So the guest finished the pull and went idle while the host CLI waits for a
completion signal that never arrives. Host-side `RUST_LOG=debug` shows the manifest resolved and
then nothing.

This is a host and guest completion-handshake problem, not a pull problem, not a network problem
and **not the macOS abort in #1192**: the Windows pack-run boot spawns a detached `_boot-vm` rather
than forking in-process, so the Objective-C fork-safety abort cannot apply here.

**Every killed bake leaves a registered `init-bake-<hash>-<pid>` machine.** It appears in
`machine list` and has to be deleted like any other machine; the next bake removes the ones 30
minutes old or older, so a run of attempts inside that window leaves one per attempt. The v1.14.6
run left `init-bake-6e96a1a9683d8fb2-8648` behind exactly this way.

## What a Windows run has to do instead

Use `--net` with an egress policy rather than the offline pattern, and say plainly that it is the
weaker isolation: the workload has network for the whole run. That is the same trade as the
network-on route in `references/macos.md`, for a different underlying reason.

## The reaper on Windows

**Key on every `_boot-vm` process the script started, not only the pack-run path.**

The `pack run` path spawns a detached `_boot-vm` with `DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP`,
and measured on the tested host, that child survives a real Ctrl-C and a kill of the CLI: about
365 MB, invisible to `machine ls`. Only killing the child ends it.

The plain foreground `machine run` orphans too, measured on v1.22.2 above: the source has no
parent-death arming on Windows, the watchdog is Unix-only and the plain `_boot-vm` spawn is also
detached. Unlike the pack-run child, it stays in `machine list` as `running (eph)`. So a Windows
port of `scripts/cleanup.sh` should reap every VM process it started rather than only the ones from
the cached route, which is the opposite of the Linux split in `references/traps.md`.
