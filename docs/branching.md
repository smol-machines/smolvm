# Branching

To stop a machine without losing its running execution, use
[`machine pause` and `machine resume`](pause-resume.md).

A branch is a live fork: an independent copy-on-write child that resumes with
the source's running processes, memory, and disk. Start the source as
branchable, then branch it:

```bash
smolvm machine start --name source --branchable
smolvm machine branch --from source --name child          # checkpoints the source wherever it is
```

Use `--freeze-source` when many independent children should branch from the
same point. The source stays paused and later branches reuse its checkpoint,
so its disk overlay does not gain another backing layer for each branch. The
source cannot run `machine exec` while frozen. The flag works with both single
and batch branches. The HTTP branch request and automatic pool creation request
accept `"freezeSource": true`; a pool retains this setting for refills.

```bash
smolvm machine branch --from source --name child --freeze-source
smolvm machine branch --from source --name child-2  # reuses the frozen checkpoint
```

On Windows, `--freeze-source` is required for a live branch.

To fan out many children from one checkpoint, the source's workload marks the
point to take it by running `smolvm-branch-ready` once its setup is done, and
names the program each child should run after it. The helper blocks in the
source, which stays parked there; in each child it hands off to that program
with the child's identity in its environment:

```bash
# the workload: install, warm up, then "fork me here, and run this in each child"
smolvm machine create --name source --image python:3.12-alpine --net -- sh -c '
  pip install -q requests
  python3 serve.py &                    # keeps running in every child
  exec smolvm-branch-ready -- python3 episode.py'

smolvm machine start --name source --branchable
smolvm machine branch --from source --count 8 --name-prefix worker --parallel 8
```

`episode.py` starts in each child with `SMOLVM_BRANCH_NAME`,
`SMOLVM_BRANCH_INDEX`, `SMOLVM_BRANCH_BATCH_ID`, and `SMOLVM_BRANCH_BATCH_SIZE`
set, plus any `--env` the branch command passed. A shell script that wants to
continue inline instead runs `eval "$(smolvm-branch-ready)"`: the same command,
whose output is those variables as `export` lines. `machine exec` sessions in a
child see them in their environment too.

When a child has its own warm-up after the branch (loading a checkpoint,
binding a port), it can report the moment it is actually usable by running
`smolvm-worker-ready`, and the branch command can wait for that instead of
for the release alone:

```bash
smolvm machine branch --from source --count 8 --name-prefix worker --wait-worker-ready
```

With `--wait-worker-ready` (window: `--worker-ready-timeout`, default 5m) a
child that never reports is torn down with its batch rather than handed back
looking alive. `machine branch-release` takes the same flags for a held pool
slot.

Container rules apply, as in Docker: the container lives as long as its main
process. `exec smolvm-branch-ready` with no program simply parks; the child
keeps running with the helper as its init. A batch branch waits
(`--ready-timeout`, default 10m) for the source to reach its branchpoint; a
single `--name` branch never waits. With `--name-prefix` or `--hold`, even a
count of one is a batch and gets the same boundary, identity, and release.

A child inherits the source's labels. `--label KEY=VALUE` on `machine branch`
sets or replaces a label on the child, so a caller that finds its machines by
label can tell children apart from their source.

Add `--branchable` to a child when it must branch again. A branchable child
costs the same as a leaf: both share the source's memory pages, and branching
the child later copies only the pages it has written since, so a deep tree of
branches pays for its changes, not for a copy of RAM at every level. `fork`,
`--golden`, and `--forkable` remain compatibility aliases. A branch takes a checkpoint of the
source in memory; `machine checkpoint` saves that same state as a durable
`.checkpoint` file that can be restored later or elsewhere
([format](../crates/smolvm-checkpoint/FORMAT.md)).

Building checkpoint tooling in Rust? [`smolvm-checkpoint`](../crates/smolvm-checkpoint)
provides incremental storage, verified file restoration, and portable export
without depending on the VM runtime.

## Disk-chain compaction

Live branches share immutable disk layers. SmolVM compacts these layers in the
background, including layers inherited from an earlier source. When an inherited
base is already deep, compaction produces a standalone disk rather than retaining
that deep base. Repeated golden → job → next golden cycles therefore do not keep
adding disk layers indefinitely.

Before a live branch approaches the disk-layer safety limit, SmolVM waits for any
in-flight compaction and finishes necessary compaction before capturing the source.
That branch can take longer and requires space for the flattened disk. The active,
writable layer is never flattened; existing children retain their disk contents.
A compaction failure fails the branch before capture instead of proceeding toward
the limit. This does not remove the separate logical branch-ancestry safety limit.

`GET /api/v1/machines/{name}` reports `diskChainDepth`: the maximum number of backing
layers across the machine's storage, overlay and cache disks. A standalone disk
has depth zero. The field is omitted when depth cannot be measured, and on bulk
list responses. It measures disk layers, not branch generation.

Compaction coordinates across CLI and server processes, and with disk-layer
garbage collection. It can shorten a frozen source's inherited chain without
replacing that source's active disk. Reader parallelism adapts to the process's
file-descriptor limit. Shallow branches do not wait for the compaction GC lock.

See [compaction QA and rollout](branch-and-checkpoint/disk-chain-compaction-qa.md)
for failure tests, temporary-space requirements and deployment precautions.

## Warm pools over the API

`smolvm serve` keeps a pool of held branches of a running branchable source and
hands one out per lease, with the job's environment and files installed before
its program runs.

```sh
J='-H content-type:application/json'
curl $J -XPOST $API/api/v1/pools -d '{"name":"p","source":"src","desiredReady":4}'
curl $J -XPOST $API/api/v1/pools/p/leases -d '{"idempotencyKey":"job-1","env":["JOB=1"],
  "files":[{"path":"job.json","dataBase64":"e30="}]}'
curl -XPOST $API/api/v1/pools/p/leases/$LEASE/heartbeat   # before expiresAt
curl -XPOST $API/api/v1/pools/p/leases/$LEASE/complete    # the worker is replaced
```

Files land under `/workspace`. A lease returns the worker's `machine` name for
the exec and file APIs. Reusing an `idempotencyKey` with a different body is
refused. Without `waitSecs` a lease fails with 503 when no worker is ready.
`PUT …/size` changes the target and `DELETE …?force=true` cancels active leases.
