# Throwaway machines on macOS

**On v1.20.2 and later the packet's default offline shape works here; use it.** This page is for
older releases, where it does not.

## Contents

- Why the offline shape does not work here before v1.20.2
- First choice: pull once, then take the network away
- Second choice: an offline persistent machine from a local image archive
- Third choice: the network-on route, and what it costs
- Which of these was run

## Why the offline shape does not work here before v1.20.2

The packet's default shape is bake once with `--oci-cache`, then run with the repo mounted and no
network. **On macOS before v1.20.2 that combination never boots.** Reproduced on macOS 26.6.2 arm64 on v1.14.2,
2026-09-08, and again on v1.18.2, 2026-09-24, three attempts each with both controls passing in the
same run:

| command | result |
|---|---|
| `--oci-cache`, no mounts | OK |
| mounts, no `--oci-cache` | OK |
| `--oci-cache` + one `:ro` mount | `agent did not become ready within 30 seconds`, 3 of 3 |

The bake itself is fine here: `machine run --net --oci-cache --image alpine -- true` reported
`baked in 5s`. It is the run with a mount that fails, which is the run you actually need.

This is [smol-machines/smolvm#1192](https://github.com/smol-machines/smolvm/issues/1192). The
pack-run path forks a session leader that never execs and, when a directory mount is present,
starts a filesystem watcher in that child; on macOS that watcher calls into CoreFoundation, and
Apple's Objective-C runtime aborts a forked, non-exec'd child that calls into ObjC. Fork versus
exec, not architecture, which is why the same combination is fine on Linux.

**v1.20.2 fixed it** (#1467): the mount watcher now runs in the CLI rather than in the forked
child, and every row of the table passed 3 of 3 on it ("Re-verified on v1.20.2" in `SKILL.md`).

`scripts/preflight.sh` reports `offline_shape=unavailable` on releases before v1.20.2, and
`scripts/bake.sh` refuses there with the reason rather than baking something you cannot use.

## First choice: pull once, then take the network away

**From v1.23.0 this route is one create with no network**, the mounts on it, then one start: the
host fetches the image ([#1536](https://github.com/smol-machines/smolvm/pull/1536)).
`README.md`, "The network is off unless you ask for it", has the commands and the v1.23.0 run.
Through v1.22.2 use the steps below.

Verified on macOS 26.6.2 arm64 on **v1.16.1**, 2026-09-15, and on **v1.18.2**, 2026-09-24. It keeps the property that matters, no
network on the run that matters, without an image archive and without `crane`:

```bash
# 1. Create with --net and NO mounts. The pull does not happen here.
smolvm machine create --name smolskill-box --net --image python:3.12-alpine -- sh -c 'while true; do sleep 3600; done'
# 2. Start once WITH the network. This is where the image is fetched.
smolvm machine start --name smolskill-box
# 3. Stop, take the network away and add the mounts in the same update, start again.
smolvm machine stop   --name smolskill-box
smolvm machine update --name smolskill-box --no-net \
    --volume "$PWD/repo:/workspace:ro" --volume "$PWD/out:/out" --volume "$PWD/script:/script:ro"
smolvm machine start  --name smolskill-box
# 4. Run the untrusted command.
smolvm machine exec --name smolskill-box -- sh -c 'python3 /script/untrusted.py > /out/result.txt'
```

**The repo is never mounted while the machine has a network.** An earlier form of this route put
the mounts on `create`, so the one start with the network also had the repo mounted; adding them in
the `update` that removes the network closes that window. Replayed on v1.18.2: `update` printed `added volume: ...` and `network:
disabled`, and the script inside read the repo, got `Read-only file system` on its write and
`urlopen error [Errno -3] Try again` on its fetch. **A mount is a directory**: a single file is
refused with `source path on host must be a directory (virtiofs limitation)`, so put the script in
a directory of its own.

Observed inside the guest at step 4: the repo file read back, `touch: /workspace/EVIL: Read-only
file system`, and the network attempt blocked (`wget: bad address 'example.com'` on v1.18.2).
**Through v1.22.2, disabling the network before the first start does not work**: the pull is at
`start`, and on v1.18.2 `machine create` refuses a registry image with no network before it gets
there, `image 'python:3.12-alpine' must be pulled from a registry, but this machine has no network,
so the pull can never succeed`.

## Second choice: an offline persistent machine from a local image archive

This supplies the image locally instead of caching it, so no network is configured at any point.
Through v1.22.2 `machine create` refuses a registry image without networking and its message names
this route itself. **If you build the archive with `crane`, it must match the guest architecture and
the legacy format.** On macOS arm64 on v1.16.1, 2026-09-15, with `crane` 0.22.1, `crane export
alpine:3.21` gave an archive in the wrong format and `crane pull --format legacy` one for the wrong
platform; `crane pull --platform linux/arm64 --format legacy` was the form that worked. Each wrong
archive cost a create, a start and a delete.

```bash
# 1. Supply the image from a local archive. No registry, so no network needed.
docker save python:3.12-alpine | smolvm machine create --name smolskill-box --image - \
    --volume "$PWD/repo:/workspace:ro" \
    --volume "$PWD/out:/out"

# 2. Start it. Still no --net anywhere.
smolvm machine start --name smolskill-box

# 3. Run the untrusted command.
smolvm machine exec --name smolskill-box -- sh -c 'python3 /workspace/calc.py > /out/result.txt'

# 4. Cancel is `machine stop`, which works, unlike Ctrl-C on a cached ephemeral run before v1.20.2.
smolvm machine stop --name smolskill-box

# 5. Delete. --force is not optional in a script.
smolvm machine delete --name smolskill-box --force
```

The mounts go on `create`, not on `exec`. `podman save` produces the same archive if you have it
instead of Docker; with `crane`, use the `crane pull --platform linux/arm64 --format legacy` form
above.

**Why this route is worth its cost:** the workload never has a network, which is the single property
that makes the offline shape worth the trouble. And cancellation is a supported command rather than
a reaper, because a persistent machine is visible to `machine list` and `machine stop` acts on it.

**It costs you the throwaway property.** The machine persists until you delete it, so a run that
writes outside the mounts leaves state behind for the next run to inherit. Delete between runs if
the workload is untrusted rather than merely unknown.

## Third choice: the network-on route, and what it costs

```bash
scripts/run.sh --route network-on --repo ./repo --out ./out -- <command>
scripts/verify.sh --route network-on --expect-file result.txt --expect 42
scripts/cleanup.sh --purge
```

Without `--oci-cache` the run pulls its own image, so **it has egress for the whole run**. Narrow
it with `--allow-host` and the run still needs to reach the registry, so the policy has to include
the registry hosts.

**State this as the weaker isolation rather than an equivalent one.** The offline route gives the
workload no network at all; this one is open for as long as the untrusted code runs, and a policy
denial in it looks like a DNS failure rather than a denial. `scripts/verify.sh --route network-on` asserts
`net=REACHED` for exactly that reason: on this route the workload reaching the network is the
expected result, and a check that asserted `blocked` would be asserting something untrue.

## Which of these was run

- **The first choice was run** end to end on macOS 26.6.2 arm64 against v1.16.1 on 2026-09-15 and
  against v1.18.2 on 2026-09-24: the value `42` in `/out`, the read-only refusal on `/workspace`
  and the lookup failure with the network removed.
- **The third choice was run** on v1.14.2 on 2026-09-08 and again on v1.18.2 on 2026-09-24:
  `run.sh --route network-on`, `verify.sh` with all six checks, the cancel path and `cleanup.sh`.
- **The second choice was run** once, by an agent following this packet, on macOS arm64 against
  v1.16.1 on 2026-09-15, with the archive built by `crane` 0.22.1 in the form above. `docker` and
  `podman` were not used, so the `docker save` line is the route `machine create`'s own error
  message recommends, not one that ran.
