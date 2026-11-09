# Per-platform arms

| | macOS arm64 | Linux aarch64 | Linux x86_64 | Windows x86_64 |
|---|---|---|---|---|
| run here | every step, v1.23.0 | every step, v1.18.2, and once on v1.22.2; a Mac checkpoint restored on v1.23.0 | not run | by hand, v1.34.0 and v1.22.2 |
| `checkpoint` file without `--branchable` | works from v1.20.0, refused before | works | worked on v1.14.2 | fails from v1.28.1 (`os error 1784`); worked through v1.28.0 |
| `pause` without `--branchable` | works from v1.20.0, refused before | works | not run | fails from v1.28.1, as the checkpoint; worked on v1.22.2 |
| `checkpoint --store` | works; needs `--branchable` before v1.24.0 | works (refused on v1.16.1) | not run | refused |
| branching | from a running source | from a running source (`frozen` on v1.16.1) | `running` on v1.14.2 | every branch needs `--freeze-source`; the source stays `frozen` |
| restored disks | `.raw` files, copy-on-write on APFS; `_restore-checkpoints` from v1.22.0, `_restore-base` before | `qcow2` layers over `.smolcheckpoint-*.raw` | not run | not measured |

## macOS arm64

macOS 27.0.1, Apple M4, v1.23.0, 2026-10-04. Every script here ran end to end. A checkpoint file
and a pause do not need `--branchable` from v1.20.0, nor `--store` from v1.24.0; `branch` still does. On v1.18.2
captures of a 1 GiB alpine machine took 1 to 5 s with a source pause of 0.027 to 0.048 s.

## Linux aarch64

Lima `linux-kvm`, Ubuntu 24.04, kernel 6.8.0-139-generic, nested virtualisation, v1.18.2,
2026-09-24, and once on v1.22.2 on 2026-10-03. Every script here ran end to end at 1024 MiB. Two things changed from v1.16.1, both
for the better: `--store` works, where v1.16.1 refused it with `this machine's runtime does not
support incremental checkpoint streaming`, and a batch branch leaves the source running, where
v1.16.1 froze it (#1327). On both dates that Lima host could not boot guests above 2048 MiB
inside smolvm's 30 s readiness window, for host reasons the `install` packet records, which is why
every machine here is 1024 MiB. On v1.23.0, 2026-10-04, a checkpoint file taken on the Mac
restored and resumed here with its RAM counter running on from where it was captured; `SKILL.md`,
"Re-verified on v1.23.0", has the run.

## Linux x86_64

Not run after v1.14.2. A run on v1.14.2 on an A10 host checkpointed an ordinary machine and left a
branch source running.

## Windows x86_64

Run by hand on 2026-11-09 on v1.34.0, Windows 11 Home build 10.0.26200 UBR 9711, PowerShell
driving the CLI through `Start-Process`. **A machine started without `--branchable` can no longer
be checkpointed or paused there.** Both fail in under 4 s and the machine keeps running:

```
Error: agent operation failed: checkpoint machine: libkrun save failed: ERR EIO capture VM: VM
snapshot/restore failed: guest-memory dump: The supplied user buffer is not valid for the
requested operation. (os error 1784)
```

On the same host, the same `checkpoint --output` of a machine started without the flag wrote a
57 to 60 MiB file on v1.22.2, v1.25.1, v1.25.4, v1.26.1, v1.27.3, v1.27.4 and v1.28.0, and failed
this way on v1.28.1, v1.31.5, v1.33.0 and v1.34.0. v1.28.1's one libkrun change reserves the
virtio-fs DAX windows instead of committing them on Windows. **Start the machine with
`--branchable`**, which every script here does: then a checkpoint file wrote 48 MiB with a 2.2 s
source pause, `pause` took 30 s, `machine resume` (not `start`, which answers `machine has saved
execution; use resume`) brought it back with its RAM counter continued (4 before, 6 after, 8 two
seconds later), and a restore with `machine create --from` carried the source's RAM token. The
rest read as on v1.22.2: `--store` refused with the message below, every branch refused without
`--freeze-source`, each child reading the source's RAM token, the source `frozen` and `exec` on it
refused.

On 2026-10-03, on v1.22.2, Windows 11 Home build 10.0.26200 UBR 9457, PowerShell driving the CLI through
`Start-Process` so `machine start` and `machine branch` returned. A checkpoint file of a machine
started without `--branchable` wrote 57 MiB in 43 s with a 3.4 s source pause, and `pause` and
`resume` worked without it; with `--branchable`, a RAM counter read 52 before a pause and 56 after
the resume. `--store` is refused: `incremental checkpoint: this machine's runtime does not support
incremental checkpoint streaming; restart it with an updated libkrun, or omit --store for a
standalone checkpoint`. `branch` without `--freeze-source` is refused with `Windows currently
requires --freeze-source; source continuation after a branch is not implemented`, for the first
branch and for every later one; with it each child read the source's RAM token, the source was
listed `frozen`, and `exec` on it was refused. A checkpoint file restored with `machine create
--from` and started. So `scripts/checkpoint.sh`, which uses `--store`, cannot run there, and a batch
branch needs the flag on every call.
