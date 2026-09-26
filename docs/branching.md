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

Add `--branchable` to a child when it must branch again. `fork`, `--golden`, and
`--forkable` remain compatibility aliases. A branch takes a checkpoint of the
source in memory; `machine checkpoint` saves that same state as a durable
`.checkpoint` file that can be restored later or elsewhere
([format](../crates/smolvm-checkpoint/FORMAT.md)).

Building checkpoint tooling in Rust? [`smolvm-checkpoint`](../crates/smolvm-checkpoint)
provides incremental storage, verified file restoration, and portable export
without depending on the VM runtime.
