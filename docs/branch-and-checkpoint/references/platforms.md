# Per-platform arms

| | macOS arm64 | Linux aarch64 | Linux x86_64 | Windows x86_64 |
|---|---|---|---|---|
| run here | every step, v1.23.0 | every step, v1.18.2, and once on v1.22.2; a Mac checkpoint restored on v1.23.0 | not run | by hand, v1.22.2 |
| `checkpoint` file without `--branchable` | works from v1.20.0, refused before | works | worked on v1.14.2 | works |
| `pause` without `--branchable` | works from v1.20.0, refused before | works | not run | works |
| `checkpoint --store` | works, and needs `--branchable` | works (refused on v1.16.1) | not run | refused |
| branching | from a running source | from a running source (`frozen` on v1.16.1) | `running` on v1.14.2 | every branch needs `--freeze-source`; the source stays `frozen` |
| restored disks | `.raw` files, copy-on-write on APFS; `_restore-checkpoints` from v1.22.0, `_restore-base` before | `qcow2` layers over `.smolcheckpoint-*.raw` | not run | not measured |

## macOS arm64

macOS 27.0.1, Apple M4, v1.23.0, 2026-10-04. Every script here ran end to end. A checkpoint file
and a pause do not need `--branchable` from v1.20.0; `--store` and `branch` still do. On v1.18.2
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

Run by hand on 2026-10-03 on v1.22.2, Windows 11 Home build 10.0.26200 UBR 9457, PowerShell driving the CLI through
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
