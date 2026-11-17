# Inherited disk-chain compaction: QA and rollout

Validated locally on 2026-10-21 against engine base `b50f8670` and cloud base
`b79d4f83`. These results are not a production deployment or cloud canary.

## Safety contract

- Replace only recognized, immutable SmolVM disk generations, never a running or
  frozen machine's active disk, arbitrary external images, or restored files with
  unrecognized names.
- Preserve guest-visible bytes, explicit zeros, target ownership and permissions.
  Existing readers keep their open inode and backing-file descriptors.
- Serialize processes compacting the same ancestor. Coordinate publication with
  layer garbage collection. Shallow no-op branches bypass the GC lock.
- Sync the completed replacement and its metadata before atomic rename, then
  sync its directory. A failed write leaves the original target intact.
- Fail necessary foreground compaction before capturing or freezing the source.
- Keep the separate logical/RAM ancestry guard. Disk compaction does not remove
  every branching limit or make RAM ancestry unlimited.
- Use the existing QCOW2 format. No guest kernel, libkrun, or database migration
  is required.

## Automated coverage

The compaction tests cover:

| Case | Assertion |
| --- | --- |
| Inherited 32-layer chain | Compacts rather than retaining the deep inherited root |
| 108 rotations through 12 golden cycles | Depth remains bounded; retained siblings retain their bytes |
| Frozen active disks above managed generations | A 32-layer chain shortens to eight without replacing active inodes |
| Storage, overlay, cache, and RAM | Branch isolation and retained sibling state survive repeated golden cycles |
| Empty/sparse disks and explicit zero mappings | No zero-chunk panic or resurrection of backing data |
| Child ownership differs from ancestor | Ancestor UID, GID, and mode remain unchanged |
| Four independent processes compact one ancestor | Publication is serialized and children retain their data |
| `RLIMIT_FSIZE` write failure | Unpublished partial is cleaned; original bytes survive; retry succeeds |
| Actual `ENOSPC` in a private tmpfs | Original bytes and chain survive; retry succeeds after freeing space |
| `SIGKILL` before and after atomic rename | Old or new complete target remains readable; GC and retry succeed |
| Existing reader across publication and GC | Already-open backing descriptors still return the original bytes |
| Killed lock holder | Process locks release and dead merge markers are reclaimed |
| 64-file-descriptor limit | Reader concurrency falls instead of exhausting descriptors |
| GC lock held during a shallow branch | The no-op fast path does not wait for GC |
| Unmanaged paths and orphan locks | Foreign images are not replaced; only safe orphan locks are removed |

Fault injection is compiled only into tests. The disk-full test mounts a small
tmpfs inside a private mount namespace and needs root; it does not fill the host
filesystem. Crash tests kill their own helper processes, not VMs belonging to
other users. Process-kill tests are not a physical power-loss test.

## Reproduce engine checks

```sh
cargo fmt --all --check
cargo test -p smolvm -- --test-threads=4
cargo clippy -p smolvm --all-targets -- -D warnings
cargo audit
cargo test -p smolvm --lib --no-run
sudo <test-executable-printed-above> agent::fork::compact::tests --include-ignored --test-threads=4
cargo build -p smolvm
```

On Linux the library suite passed **1,582 tests**, with ten existing ignored
tests. Running the compaction module as root, including its disk-full test,
passed **33 tests**. Native M4 Max validation passed **1,423 tests**. Strict
Clippy passed on both platforms. The native Mac run exercises tests, not the
Linux KVM acceptance script below. `cargo audit` passed under the repository's
existing policy with seven allowed warnings; this change adds no dependencies
and does not resolve those existing advisories.

The Linux command also passed the binary, enabled integration, and documentation
tests. Tests requiring embedded runtime features or privileged mounts retain
their existing ignores; they are not claimed as executed by that command.

The non-root compaction module also passed ten consecutive four-thread runs
(320 passing test executions) to exercise process-contention and crash recovery
repeatedly.

The default highly parallel Linux suite exposes an existing
`network::port_forward::tests::ports_are_added_and_removed_while_running_and_reach_their_guest_port`
timing failure. The same failure reproduced on the untouched engine base. That
test passes alone and in the full four-thread suite above; it has not been
skipped or modified by this change.

The real-VM acceptance script needs Linux KVM, `qemu-img`, Python, curl, and the
installed SmolVM runtime/rootfs. Set `SMOLVM_LIB_DIR` and
`SMOLVM_AGENT_ROOTFS` if they are not in their normal locations:

```sh
SMOLVM_BIN="$PWD/target/debug/smolvm" bash tests/test_inherited_disk_chain.sh
SMOLVM_TEST_FREEZE_GOLDENS=1 SMOLVM_BIN="$PWD/target/debug/smolvm" bash tests/test_inherited_disk_chain.sh
```

Each mode makes 40 actual branches across four golden cycles. It checks markers
in storage, overlay, cache and RAM; retained children; actual chain depth with
`qemu-img`; creation of a standalone managed generation; and the real node HTTP
detail response against the measured maximum depth. The second mode freezes
each old golden when creating its successor. The script uses an isolated
temporary state directory, deletes its own machines, and retains logs.

Both modes passed on the final engine binary: **80 real branches** in total.
The final live-mode disk maximum was 15; the frozen-mode maximum was 16, below
the 32-layer guard. All 18 detail responses matched `qemu-img`. Frozen machines
also exercise the existing server reconnect probes: four frozen sources exceed
a ten-second startup allowance, so the script allows up to 120 seconds and
prints server logs on failure. This does not change server startup behavior.

## Cloud checks

In the companion cloud worktree:

```sh
cargo fmt --all --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

The workspace checks pass. Detail-route tests cover measured depth, standalone
depth zero, old nodes without the field, node 404, and a five-second node delay
bounded by a one-second lookup timeout. List requests and missing cloud machines
do not trigger node detail lookups. Invalid, negative, or absent depth is omitted,
not reported as zero. This optional measurement is not persisted in the database.

## Costs and rollout gates

A deep chain occasionally requires foreground copying before branching. Budget
temporary space for a materialized replacement, which can be much larger than
the original sparse or compressed delta. Disk-full errors are safe failures,
not automatic capacity expansion. Simultaneous compactions consume storage
bandwidth; a low descriptor limit reduces reader parallelism. No build/test
wall-clock improvement is claimed by these integrity tests.

1. Run CI for both repositories. Drain one worker's placements and outstanding
   branch/compaction operations before upgrading it. Upgrade CLI and server
   processes sharing a state directory together: older garbage collectors do
   not honor the new process locks. Do not run mixed versions over that root.
2. Upgrade workers before relying on cloud depth reporting. The optional cloud
   field tolerates old nodes, but cannot fix their branching behavior.
3. Canary live and frozen golden workflows on the worker, including retained
   siblings. Verify storage, overlay, cache and RAM contents and confirm depth
   stays below the disk guard. Re-run the customer's actual workflow; synthetic
   golden tests do not replace QM/Saleor validation.
4. Watch branch p50/p95 latency, compaction duration/errors, free disk space,
   descriptor use, measured depth, and expected source running/frozen state.
   Expand only after the canary is clean under realistic concurrency and disk
   occupancy. No production canary has been performed as part of these results.
5. For rollback, drain operations again and restore a consistent engine version
   across the state root. Flattened disks remain ordinary QCOW2 files with the
   same contents. No database rollback is needed; an older engine can resume
   accumulating depth, so continue monitoring it.
