# Teardown on Windows

**Run on 2026-10-03 against smolvm v1.22.2** on Windows 11 Home build 10.0.26200 UBR 9457 x86_64,
as the cleanup after runs that had created machines, packs and four abandoned `--oci-cache` bakes.
The sequence below removed everything: `%LOCALAPPDATA%\smolvm` held 291 MB at removal, no smolvm
process was left, the firewall rule count matched the one taken before those runs (715), no
firewall filter named smolvm, and the 70 entries of `%LOCALAPPDATA%` matched the listing taken
before them. The sizes quoted further down are from the first run, on v1.14.2.

**On v1.16.0 a third directory, `%LOCALAPPDATA%\smolvm-libs`, appeared once a packed stub had
run**, holding the extracted `krun.dll` and `libkrunfw.dll` (62 MB). It did not appear on v1.22.2,
where no packed stub could run. Remove it with the other two.

`scripts/preflight.sh`, `scripts/cleanup.sh` and `scripts/verify-clean.sh` are bash and do
not run here. Follow this page instead.

## Why Windows teardown matters more than elsewhere

**smolvm's state cannot be relocated on Windows.** There is no `SMOLVM_DATA_DIR` in the Windows
binary, and setting `$env:LOCALAPPDATA` moves nothing: smolvm resolves the known folder through
the Windows API, which ignores the variable, and writes to the real `%LOCALAPPDATA%\smolvm`
regardless. There is no isolated-HOME trick, so every test run writes into the real profile and
teardown is the only way back.

**The sizes are the surprise.** `%LOCALAPPDATA%\smolvm` reached **30756 MB** in one set of runs,
because each machine's storage and overlay images are sparse files with 20 GiB and 10 GiB
apparent size. Those runs' own working directory was 1454 MB. A user who deletes only their
working directory leaves 30 GB behind with nothing pointing at it.
`%LOCALAPPDATA%\smolvm-pack` separately reached 92 GB apparent after three `pack run`s of one
alpine pack.

## The sequence

On Windows there is one state tree per user and no way to scope by `HOME`, so this sequence
removes every machine in it and stops every process of that smolvm, another session's included.
Read the list in step 1 before running the rest on a shared host.

```powershell
$exe = "<the directory you unzipped>\smolvm.exe"

# 1. delete every machine (--force, and --cascade for branch sources)
& $exe machine list
& $exe machine delete --name <each> --force --cascade

# 2. stop anything still running from that smolvm.exe
Get-Process | Where-Object { $_.Path -eq (Resolve-Path $exe).Path } | Stop-Process -Force

# 3. remove the state smolvm created outside your working directory
Remove-Item -Recurse -Force "$env:LOCALAPPDATA\smolvm"
Remove-Item -Recurse -Force "$env:LOCALAPPDATA\smolvm-pack"   # exists once packs have run
Remove-Item -Recurse -Force "$env:LOCALAPPDATA\smolvm-libs"   # seen on v1.16.0 once a packed stub had run

# 4. remove your own working directory
Remove-Item -Recurse -Force <your scratch dir>
```

The v1.22.2 run matched step 2 on any path containing `smolvm`; the exact-path form above is
narrowed from it and has not been run on Windows.

**A killed `--oci-cache` bake leaves a registered machine** named `init-bake-<hash>-<pid>`. It
appears in `machine list` and has to be deleted like any other machine; the next bake removes the
ones 30 minutes old or older, so a run of attempts inside that window leaves one per attempt. On
the tested host the bake never completed at all, so this is not a rare case:
the helper VM finished its pull and went idle while the host CLI waited forever for a completion
signal, and every attempt had to be killed.

## Verify, and do not skip this

```powershell
Get-Process | Where-Object { $_.Path -like '*smolvm*' }                       # expect nothing
Get-ChildItem $env:USERPROFILE,'C:\ProgramData' -Recurse -Force -Filter '*smolvm*' -EA SilentlyContinue
Get-NetFirewallApplicationFilter | Where-Object { $_.Program -like '*smolvm*' }
```

All three returned nothing after the sequence above.

## Proving a host was left clean

The method used on the tested host: record
`path|size|mtime` for `%USERPROFILE%` and `C:\ProgramData` before and after, excluding your own
working directory, then compare. `%LOCALAPPDATA%`, `%APPDATA%` and `%TEMP%` are all **inside**
`%USERPROFILE%`, so listing them separately quadruples the work for no extra coverage: the naive
version of that scan did not finish, and the de-duplicated one took 167 s for 982653 entries.
The assertion that matters is that no new entry matches `smolvm|krun|libkrunfw`.

## One more Windows process fact

The `pack run` boot path spawns a **detached** `_boot-vm` rather than forking, with
`DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP`. Measured on the tested host: the child survives a
real `Ctrl-C` and a kill of the CLI, holds about 365 MB, and is invisible to `machine ls`. Only
killing the child ends it, so step 2 above is not optional on Windows either.
