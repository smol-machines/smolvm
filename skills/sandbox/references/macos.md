# Sandboxing on macOS

## Contents

- Why the offline shape does not work here
- First choice: an offline persistent machine from a local image archive
- Second choice: the network-on route, and what it costs
- Which of these was run

## Why the offline shape does not work here

The packet's default shape is bake once with `--oci-cache`, then run with the repo mounted and no
network. **On macOS that combination never boots.** Reproduced on macOS 26.6.2 arm64 on v1.14.2,
2026-09-08, three attempts with both controls passing in the same session:

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

`scripts/preflight.sh` reports `offline_shape=unavailable` here, and `scripts/bake.sh` refuses with
the reason rather than baking something you cannot use.

## First choice: an offline persistent machine from a local image archive

This keeps the property that matters, **no network on the run at all**, by supplying the image
locally instead of caching it. `machine create` refuses a registry image without networking and its
message names this route itself.

```bash
# 1. Supply the image from a local archive. No registry, so no network needed.
docker save python:3.12-alpine | smolvm machine create --name smolskill-box --image - \
    --volume "$PWD/repo:/workspace:ro" \
    --volume "$PWD/out:/out"

# 2. Start it. Still no --net anywhere.
smolvm machine start --name smolskill-box

# 3. Run the untrusted command.
smolvm machine exec --name smolskill-box -- sh -c 'python3 /workspace/calc.py > /out/result.txt'

# 4. Cancel is `machine stop`, which works, unlike Ctrl-C on an ephemeral run.
smolvm machine stop --name smolskill-box

# 5. Delete. --force is not optional in a script.
smolvm machine delete --name smolskill-box --force
```

The mounts go on `create`, not on `exec`. `crane export` or `podman save` produce the same archive
if you have those instead of Docker.

**Why this is the first choice:** the workload never has a network, which is the single property
that makes the offline shape worth the trouble. And cancellation is a supported command rather than
a reaper, because a persistent machine is visible to `machine list` and `machine stop` acts on it.

**It costs you the throwaway property.** The machine persists until you delete it, so a run that
writes outside the mounts leaves state behind for the next run to inherit. Delete between runs if
the workload is untrusted rather than merely unknown.

## Second choice: the network-on route, and what it costs

```bash
scripts/run.sh --route network-on --repo ./repo --out ./out -- <command>
scripts/verify.sh --route network-on --expect-file result.txt --expect 42
scripts/cleanup.sh --purge
```

Without `--oci-cache` the run pulls its own image, so **it has egress for the whole run**. Narrow
it with `--allow-host` and the run still needs to reach the registry, so the policy has to include
the registry hosts.

**State this as the weaker sandbox rather than an equivalent one.** The offline route reaches no
network at all; this one is open for as long as the untrusted code runs, and a policy denial in it
looks like a DNS failure rather than a denial. `scripts/verify.sh --route network-on` asserts
`net=REACHED` for exactly that reason: on this route the workload reaching the network is the
expected result, and a check that asserted `blocked` would be asserting something untrue.

## Which of these was run

- **The second choice was run**, end to end on macOS 26.6.2 arm64 against v1.14.2 on 2026-09-08:
  `run.sh`, `verify.sh` (all five checks), the cancel path and `cleanup.sh`.
- **The first choice was not re-run.** It needs a `docker`, `crane`, `podman` or `nerdctl` binary to
  produce the image archive and this host has none of them. The commands above are the route the
  runbook names and the one `machine create`'s own error message recommends; treat them as
  untested here.
