---
name: teardown
description: "Stops every smolvm machine a session started, removes smolvm's state, and proves the host is clean. Use after any smolvm session; when a machine seems to have survived a Ctrl-C or a crash; when disk space has disappeared; when uninstalling smolvm; when tearing down the Kubernetes runtime from a node; or when a borrowed or shared host has to be handed back with nothing left behind. Also use it as the cleanup step for other smolvm work, because the obvious assertions here give false results. Do not use it to delete machines another session created: it removes only what a script recorded under its own name prefix."
---

# Leaving nothing running and nothing behind

Verified on **smolvm v1.23.0** on macOS arm64, 2026-10-04, and on **v1.18.2** on Linux aarch64,
2026-09-24. This packet exists on its own because **the obvious cleanup steps fail here**: the
obvious assertion gives a false failure, the obvious reaper matches the wrong process or nothing
at all, and killing a wrapper around a run does not stop its machine. Anything that starts machines
needs this more than it needs any single feature.
The Linux runs used the scripts of their date; this version's preflight and cleanup scripts ran
on Linux aarch64 on v1.22.2 on 2026-10-03.

The cleanup scripts of credentials, dev-env, docker-in-machine, gpu-cuda and install are this
packet's `scripts/cleanup.sh` with the `PACKET=` line changed; branch-and-checkpoint, local-api, pack
and throwaway-machine build on it and add flags of their own.

## Procedure

The commands below are relative to this packet's directory; its scripts write nothing to the
working directory, so running them from there is safe.

**1. See what is there.** Read-only: deletes nothing, starts no VM.

```bash
scripts/preflight.sh
```

It reports each state directory with its size, whether an `--oci-cache` bake cache exists,
whether the launcher symlink and the `PATH` block are present, and whether state can be relocated
on this platform.

**2. Delete the machines your scripts created, and report the rest.**

```bash
scripts/cleanup.sh            # report leftover VM processes
scripts/cleanup.sh --reap     # and kill them
```

`--reap` kills every VM process under this `HOME`, a running machine you meant to keep included, so
run plain `cleanup.sh` first to read the list, and reap only when nothing there should keep running.

`cleanup.sh` waits up to 20 seconds, polling the machine list, and prints `waiting=up to 20s`
first: an ephemeral machine's entry retires after its run returns.

Only machines recorded in the state file are deleted, so a machine you or another session created
by hand is never deleted. A script records what it creates with
`scripts/cleanup.sh --record <name>`, and names must carry the `smolskill-` prefix or the delete
is skipped. `--purge` removes the state file once the list is empty.

**When the user asks you to clean up machines they made themselves**, which is what "clean up
after me" usually means, nothing is recorded and the script reports them as `machines=remaining`
and leaves them. That is the guard working, not the end of the job. List them, confirm they are
the user's and not another session's, and delete each by name. `smolvm machine list --json` gives
each machine's `created_at`, in Unix seconds, and its image: one created before the user's session
began, or under a name they do not recognise, is not theirs to delete without asking.
`machine stop` on a machine that is already stopped prints `Machine '<name>' is not running` and
exits 0, so the stop line is safe either way:

```bash
smolvm machine list
smolvm machine stop   --name <NAME>
smolvm machine delete --name <NAME> --force --cascade
```

Then run `scripts/cleanup.sh` again for the process check, and step 3.

The state file lives under `${XDG_STATE_HOME:-$HOME/.local/state}/smolvm-skills/`, outside
`~/.smolvm` and outside smolvm's own caches. Nothing here edits smolvm configuration.

**3. Prove it.**

```bash
scripts/verify-clean.sh
HOME=/tmp/sk SMOLVM=/tmp/sk/.local/bin/smolvm scripts/verify-clean.sh --protected "$HOME/.smolvm" \
    --protected "$HOME/.local/share/smolvm" --protected "$HOME/.cache/smolvm"   # typed in your real shell
```

Typed in your real shell, `$HOME` expands to the real profile before `HOME=/tmp/sk` applies, so the
checks audit the scratch profile and the three `--protected` directories are the real
installation's binary, data and cache. On macOS the last two are
`~/Library/Application Support/smolvm` and `~/Library/Caches/smolvm`; a `--protected` directory
that does not exist fails rather than passing. `SMOLVM=` points the scan at the scratch install's
binary; on Linux, run it with `XDG_DATA_HOME` and `XDG_CACHE_HOME` unset, as the install was.
Anything the real installation wrote today counts, and a running real machine writes to its cache
directory. Stop the real machines first, and pass `--since` with the time the test began, such as
`--since "2026-10-03 14:00"`.

**Every check here is scoped to the `HOME` it runs under**, and the `audited_home=` line says
which profile the result describes. Run it under a different `HOME` and it reports a clean host no
matter what is running elsewhere: an agent that hit `machines=FAIL` did exactly that, re-ran the
script under a fresh `mktemp -d`, got `result=clean`, and reported the host clean while a VM was
still running.

Each check prints `ok` or `FAIL expected=... actual=...`, and the script exits non-zero if any
failed. When the `HOME` you are auditing is the only installation there is nothing to protect:
leave the flag off, and the `protected=not_checked` line it then prints is expected.
`--protected <dir>` asserts nothing under that directory was written today, which is how you show
a test run under a scratch `HOME` did not reach a real installation. It is repeatable, and a leak
lands in the data and cache directories rather than the prefix, so name all three. It takes an
installation's directories, not a home directory: pointed at a whole home it counts every file
written there today and reports `result=dirty`.

**4. Reclaim space, or remove smolvm entirely.**

```bash
# machine prune: unreferenced layers; starts the machine if it is stopped. --all also
# drops cached images, except for a machine created from an image
smolvm machine prune --name <NAME>
smolvm pack prune
curl -sSL https://smolmachines.com/install.sh | bash -s -- --uninstall
```

`references/locations.md` has the full layout, what the uninstaller removes, and the two things it
deliberately leaves. On v1.18.2 on macOS it also leaves `~/Library/Caches/smolvm-registry`, and on
v1.23.0 `smolvm-image-archives` beside the cache directory on both hosts, without saying so; remove
those by hand after `--uninstall`.

## The traps that make this a packet

Full detail with the observations behind each is in `references/traps.md`.

- **`Ctrl-C` on the CLI stops the machine from v1.20.2; killing a wrapper around it does not.** On
  v1.22.2 the killed wrapper's CLI and VM kept running, listed as `vm-<id> running (eph)`;
  `smolvm machine stop --name vm-<id>` ends both, and the entry stays `stopped (eph)` until
  `machine delete --force`. Before v1.20.2 an interrupted CLI left its VM running, unlisted on
  v1.14.x, which is the case the reaper still covers.
- **The two obvious reapers fail in opposite directions.** `pgrep -f _boot-vm` matches the cleanup
  script itself; `readlink /proc/<pid>/exe` is denied for a VM process. Matching `argv[1]` misses
  the forked VMs a pack run starts. On Linux VM processes rename themselves to `libkrun VM`, or to
  `VM:<hostname>` when `HOSTNAME` is exported, which no shell can hold, so `cleanup.sh` matches
  that in `/proc/<pid>/comm`; on macOS it matches the executable path and parent chain. Both are
  scoped to this `HOME`.
- **Asserting "no machines" straight after `machine run` can fail on a healthy host**: the entry
  retires after the command returns.
- **`machine delete` needs `--force` in a script**, and `--cascade` for a branched machine. On
  v1.17.0 and later a delete without it exits 1; before that it printed `Cancelled`, exited 0 and
  left the machine.
- **A paused machine refuses `stop`** with `machine has saved execution; use resume or delete`;
  `delete --force` removes it and its saved execution.

And one false alarm: **`ls ~/.cache/smolvm/vms/ | wc -l` is not a leak check.** On Linux, after
`machine create --from` or a checkpoint restore, `_shared` lives there: the shared pack store. Both
scripts exclude it. An `--oci-cache` bake goes to `init-layers/` beside `vms/` and to the pack
cache. The opposite case is real residue: **a boot that timed out leaves its VM directory**,
`verify-clean.sh` reports `vm_dirs=FAIL`, and running `smolvm serve start` once reclaims it. And
one cache that is sensitive: **on macOS smolvm keeps a clone of the last restored checkpoint**,
memory included, in `vms/_restore-base`, after every machine and checkpoint is gone.
`verify-clean.sh` reports it as `restore_base=present` rather than as a leak; remove it with
`rm -rf` once no restore is running.
From v1.22.0 it is `vms/_restore-checkpoints`, reported as `restore_cache=present`;
`references/traps.md` has its size and how to turn it off.

**A machine named `image-seed-<hash>-<pid>` or `init-bake-<hash>-<pid>` is smolvm's own helper.**
From v1.22.0 the first run of a registry image builds a shared seed of it in a helper machine, and
the seed itself lives in `image-seeds/` beside `vms/`. When that run is interrupted, or the helper
cannot boot, the helper can stay listed as `created` or `stopped`: three did on Linux aarch64 on
v1.22.2, at 8192 MiB each whatever the run asked for. It is neither the user's nor another
session's; delete it by name with `--force`.

## Security defaults, and why they are the defaults

- **Cleanup deletes only what it was told it created.** A shared host can carry another session's
  machines, and during the runs behind this packet it did: a second VM under a different `HOME`
  was live throughout. `cleanup.sh` listed only the processes whose boot config sits under its own
  state tree and left the other one running. A cleanup script that kills every smolvm process is
  fine on your laptop and destructive on a build agent.
- **`--reap` is opt-in, and without it the script only reports.** With it, each `vm_process=` line
  is killed as it is printed. Killing a VM is not recoverable and the VM cannot be identified from
  `machine list`, so the default is to report.
- **Nothing here escalates privilege.** The one place teardown needs `sudo` is the Kubernetes
  runtime, which installs outside your home directory; those commands are in
  `references/kubernetes.md` for you to run and read, not wrapped in a script.
- **The uninstaller leaves `~/.config/smolvm` and your `PATH` line on purpose**, because those
  hold registry credentials and a change you made to your own shell profile.

## Platform arms

- **macOS arm64**: the scripts were run here on v1.23.0. **Linux aarch64**: on v1.18.2, and once
  on v1.22.2.
- **Linux x86_64**: the procedure was verified on v1.14.2 on an NVIDIA A10 cloud host. The
  scripts themselves were not re-run there.
- **Windows x86_64**: `references/windows.md`, **run on 2026-10-03 against v1.22.2** on
  Windows 11 Home build 10.0.26200 UBR 9457 as the cleanup after runs that had created
  machines, packs and bakes, after which the profile matched its listing from before them. The
  scripts are bash and do not run there. State cannot be relocated there, and one set of runs left
  30 GB in `%LOCALAPPDATA%\smolvm`.
- **Kubernetes nodes**: `references/kubernetes.md`. The sweep was verified on Ubuntu 22.04 x86_64
  with k3s on v1.14.2, not re-run since; the lines for the `RuntimeClass`, the node label and the
  drop-in are read from the repository's k3s scripts at v1.22.2 and were not run.

## Eval prompts, and what they produced

On macOS arm64 on v1.23.0, under an isolated `HOME`:

**1. "I ran some smolvm machines. Clean up after me and show me the host is clean."** A machine
created, started, recorded and cleaned up: `Deleted machine: smolskill-td`, `machines=clean`,
`vm_processes=none`, then `machines=ok`, `vm_dirs=ok`, `vm_processes=ok`, `result=clean`.

**2. "Is anything still running that `smolvm machine list` cannot see?"** On v1.22.2 and v1.23.0 an
interrupted run stays listed, so the answer is "nothing the list cannot see"; the reaper still
names the process and its boot config. With a wrapper killed:

```
vm_process=89092 config=/tmp/u23/Library/Caches/smolvm/vms/ea8c396d10b0f0b9/boot-config.json
  killed 89092
```

**3. "Prove my test run did not touch my real smolvm install."** `verify-clean.sh --protected
$HOME/.smolvm` against the real installation beside the isolated one:
`protected_untouched_since_2026-10-04:<dir>=ok` for each `--protected` directory, and
`result=clean`.

## Re-verified on v1.23.0

Run 2026-10-04 PT against v1.23.0 from the published release, checksum checked, under a fresh
isolated `HOME` on macOS 27.0.1 arm64, once. On Lima `linux-kvm` (Ubuntu 24.04 aarch64) the
checks named below ran once, so the Linux stamp stays on its earlier release.

macOS: eval 1 gave `result=clean`. `SIGINT` and `SIGKILL` to the CLI each left no VM process at
t+1 s; a killed wrapper left `vm-0072df9e running (eph)` and its `_boot-vm`, which `cleanup.sh
--reap` found and killed. A delete without `--force` exited 1 with the confirmation message, a
paused machine refused `stop` with `machine has saved execution; use resume or delete`, and a
second `machine stop` of a missing name gave `vm_dirs=FAIL` until `serve start` printed `Reclaimed
1 dangling VM data dir(es)`. Eval 3 gave `protected_untouched_since_2026-10-04:<dir>=ok` for each
of the real installation's three directories. New beside `vms/`: `registry-tokens/`. After every
packet had run, `--uninstall` left `Library/Caches/smolvm-image-archives`, 24 MB;
`references/locations.md` has it.

Linux aarch64: `verify-clean.sh` gave `result=clean`, and `--uninstall` left
`~/.cache/smolvm-image-archives` there too.

## Re-verified on v1.22.2

Run 2026-10-03 PT against v1.22.2 from the published release, checksum checked, under an isolated
`HOME` on macOS 27.0.1 arm64, twice, the second time from a fresh `HOME`. On Lima `linux-kvm`
(Ubuntu 24.04 aarch64) on 2026-10-03 guests above 2048 MiB timed out, so the Linux lines below are
a single run and the Linux stamp stays on its earlier release.

macOS: eval 1 gave `result=clean` with `protected_untouched_since_2026-10-03=ok`, from the
script's earlier one-directory form. `SIGINT` and
`SIGKILL` to the CLI each left no VM process at t+1 s; a killed wrapper left `vm-90dd19c7 running
(eph)` and its `_boot-vm`, which `cleanup.sh --reap` found and killed. A delete without `--force`
exited 1 with the confirmation message, a paused machine refused `stop`, and a second `machine
stop` of a missing name gave `vm_dirs=FAIL` until `serve start` printed `Reclaimed 1 dangling VM
data dir(es)`. After every packet had run, the final check said `result=clean`.

Linux aarch64: eval 1 clean, the delete and pause refusals the same, and three `image-seed-*`
helpers left listed by interrupted and failed first boots. Linux was last verified on v1.18.2.

## What was not run

- **Windows through a script.** The sequence on `references/windows.md` was run by hand.
- **Kubernetes.** `references/kubernetes.md` records a sweep verified on an Ubuntu 22.04 x86_64 k3s
  node on v1.14.2, not re-run since. Its lines for the `RuntimeClass`, the node label and the
  drop-in are read from the repository's k3s scripts at v1.22.2 and were not run.
- **Linux x86_64.**
- **The macOS `hdiutil` mount-point case.** `references/traps.md` records that `rm -rf` on the
  pack cache can fail with `Resource busy` and what the uninstaller does about it. No pack was
  created in the runs recorded here, so that path was not exercised.
- **The shared pack store.** No `_shared` store existed on either host, so the exclusion these
  scripts carry was exercised only against its absence.

## Related packets

- `install` for what the install lays down, which is what you are removing.
- Every other packet's `scripts/cleanup.sh` is built from this one.
