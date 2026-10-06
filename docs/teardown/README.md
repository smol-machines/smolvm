# Leaving nothing running and nothing behind

smolvm spreads state across four places, and the hard part is not deleting them: it is knowing
what is still running. An interrupted run can leave a VM alive with its workload going, and
the obvious checks either miss it or report machines that do not exist.

`SKILL.md` is the procedure, with a reaper that matches the VM process's name on Linux and its
executable and parent on macOS, rather than a string in a command line. `references/locations.md` has the full tree per platform,
`references/traps.md` the measurements, `references/kubernetes.md` the node case.

## What exists, and where

Measured on macOS arm64 after one install and one machine:

| Path | What it holds | Size after a first boot |
|---|---|---|
| `~/.smolvm` | the binary and its bundled libraries | about 92 MB |
| `~/.local/bin/smolvm` | the launcher symlink on your `PATH` | a link |
| `~/Library/Application Support/smolvm` | the agent rootfs and the machine registry | about 48 MB |
| `~/Library/Caches/smolvm` | one directory per machine: disks and pulled layers | grows with each machine |

On Linux the last two are `~/.local/share/smolvm` and `~/.cache/smolvm`. A separate
`~/.local/state/smolvm-skills` holds the list of machines this documentation's scripts created, so
a cleanup deletes what it made and nothing else. `~/.config/smolvm` appears only once you have
logged in to a registry, and the uninstaller leaves it alone on purpose.

## Removing it

```bash
curl -sSL https://smolmachines.com/install.sh | bash -s -- --uninstall
```

That removes the install prefix, the launcher, the data directory and the cache, and tells you it
has left your shell profile's `PATH` line and your registry credentials, which are yours to remove.

## Before you remove anything, find what is running

```bash
scripts/preflight.sh       # read-only: what state exists, with sizes
scripts/cleanup.sh         # report leftover VM processes
scripts/cleanup.sh --reap  # and kill them
scripts/verify-clean.sh    # expect result=clean, and read audited_home
```

`verify-clean.sh` is scoped to the `HOME` it runs under and says which one in `audited_home=`. Run
it under a different `HOME` and it reports a clean host whatever is running elsewhere.
