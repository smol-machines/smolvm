# smolvm Tests

Integration tests for smolvm. All tests invoke the `smolvm` binary directly
against real VMs — no mocking.

---

## Runner: `run_tests.sh`

Single entry point for all test suites.

```bash
./tests/run_tests.sh                      # all 11 feature suites (~10 min)
SMOLVM_SKIP_SLOW=1 ./tests/run_tests.sh   # skip tests with long sleeps (~5 min)
./tests/run_tests.sh bare network         # specific groups only
```

### Feature suites (run by default)

| Group | Suite file | Tests | Notes |
|---|---|---|---|
| `bare` | `test_machine_bare.sh` | 22 | Lifecycle, exec, shell, file I/O, observability |
| `db` | `test_db.sh` | 6 | DB state persistence, VM state transitions |
| `network` | `test_network.sh` | 17 | Network disable, DNS, egress, DNS filter, Smolfile allow_hosts |
| `volumes` | `test_volumes.sh` | 6 | virtiofs mounts, /workspace priority |
| `ports` | `test_ports.sh` | 2 | Port mapping, cross-VM conflict detection |
| `storage` | `test_storage.sh` | 12 | Overlay, image list, prune, storage resize |
| `resources` | `test_resources.sh` | 8 | CLI validation — no VMs required |
| `reliability` | `test_reliability.sh` | 5 | Concurrency, state probe, ls-does-not-kill-vm |
| `run` | `test_machine_run.sh` | 25 | Ephemeral `machine run` scenarios |
| `image` | `test_machine_image.sh` | 13 | Image-based VMs, exec-join, large stdout |
| `packed` | `test_machine_packed.sh` | 2 | `.smolmachine` create and cp |

### Extended suites (opt-in only)

These are not included in the default run. Pass the group name explicitly:

```bash
./tests/run_tests.sh cli
./tests/run_tests.sh api
./tests/run_tests.sh virtio-net
./tests/run_tests.sh smolfile
./tests/run_tests.sh pack
./tests/run_tests.sh pack-quick     # pack tests, skip large image pulls
./tests/run_tests.sh gpu            # requires GPU hardware
```

| Group | Suite file | Tests |
|---|---|---|
| `cli` | `test_cli.sh` | 10 |
| `api` | `test_api.sh` | 25 |
| `virtio-net` | `test_virtio_net.sh` | 6 |
| `smolfile` | `test_smolfile.sh` | 49 |
| `pack` / `pack-quick` | `test_pack.sh` | 37 |
| `gpu` | `test_gpu.sh` | 14 |

### Environment variables

| Variable | Effect |
|---|---|
| `SMOLVM` | Override binary path |
| `SMOLVM_SKIP_SLOW=1` | Skip tests with intentional sleeps ≥ 25 s (docker-in-vm, ls-probe loops, egress refresh) |
| `TEST_FILTER` | Only run tests whose display name contains this substring |
| `FAIL_FAST=1` | Stop on first failure |

---

## Unit tests

No VM required. Run via cargo:

```bash
cargo test
```

---

## Benchmarks

```bash
./tests/bench_vm_startup.sh         # VM cold/warm start time
./tests/run_tests.sh bench          # same, via runner
```

---

## Binary discovery

Tests find the `smolvm` binary in this order:

1. `$SMOLVM` environment variable
2. `target/release/smolvm` (cargo build output)
3. `dist/smolvm-*-darwin-*/smolvm` or `dist/smolvm-*-linux-*/smolvm`

---

