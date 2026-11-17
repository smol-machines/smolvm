# macOS storage seed validation — 2026-10-22

Host: M4 Max, Apple silicon, 36 GiB RAM. Baseline: main at `15c11b69`
(v1.31.2, including the per-pack APFS template cache). Both binaries used
the same runtime libraries, agent rootfs and Cargo development profile with
`profile.dev.package.smolvm.opt-level=2`. These are single observations, not
release-build benchmarks or statistical latency percentiles.

## Paired 100k-file reproduction

The same 19 MB pack contains 100,000 files of 2,000 bytes, plus three files
covering case-sensitive names and hard links. Each arm starts with a separate,
empty cache. Start and the first verified read are timed separately from create.

| Operation | Main | Storage seed |
| --- | ---: | ---: |
| First create | 50.414 s | 5.393 s |
| Repeat create | 0.041 s | 0.036 s |
| Start first machine | 0.661 s | 0.246 s |
| Count all files and verify case-distinct contents | 21.931 s | 1.217 s |

First create improves 9.3×. Create, start and verification together take
73.006 s versus 6.855 s. The verification includes a full tree walk, not just
one file read; its time is not a general application-performance claim.

## Larger entry-count fixture

A synthetic pack expands the same workload to 580,003 files under `/srv`.
Its layer TAR is 1,497,415,680 bytes and its compressed pack is 22,406,960
bytes. It is **not** the reported 3.2 GB customer pack, and does not reproduce
that pack's data volume or compressibility.

| Operation | Storage seed |
| --- | ---: |
| First create | 27.589 s |
| Repeat create | 0.051 s |
| Start first machine | 0.941 s |
| Count files and verify metadata | 7.331 s |

The fixture also checks a GNU-PAX user xattr and file capability, UID/GID,
hard-link identity, symlink target and ownership, case-distinct contents and
the last generated file's size. An earlier experiment lost xattrs; that seed
format was discarded. Format 2 explicitly extracts xattrs inside Linux.

## Lifecycle checks

- Three simultaneous HTTP creates from one cold 100k-file pack finish in
  5.892–5.908 s and publish exactly one seed; a subsequent HTTP create takes
  0.014 s. Starting the machine and checking its files succeeds.
- Deleting the cached seed does not prevent an existing machine from starting
  and reading its files.
- A seeded machine exports as a normal container pack and reimports with the
  expected file count, private-file contents and symlink ownership.
- Branch isolation, branch stop/start, portable checkpoint capture and restore
  pass. Restore is checked under a fresh profile with the original pack moved
  away.
- Killing an importer after its helper launches leaves one temporary staging
  directory. A subsequent import succeeds and reclaims it and the marked
  helper directory; no seed helpers remain.
- Insufficient-disk preflight fails without publishing a partial seed.
- An explicit 1 GiB disk takes the previous host-layer import path, starts
  successfully and passes the 100k-file check without increasing its capacity.
- Pinned-source parsing keeps reading the original open pack when its path is
  replaced. Descriptor-relative disk installation cannot overwrite a new
  machine when the original directory is renamed or deleted during a retry.
- Linux library tests: 1,603 passed, 10 ignored. Native macOS storage-seed unit
  tests: 13 passed. Linux and macOS all-target Clippy checks pass with warnings
  denied.
- The final hardened binary passes three simultaneous cold HTTP creates
  (6.0 s each, one prepared seed), a warm HTTP create (0.021 s), guest metadata
  checks, restart after cache eviction, and interrupted-import recovery with
  no abandoned helper or staging directory remaining.

The paired performance measurements precede the final descriptor-relative
installation and pinned-source parsing hardening, which changes publication
rather than extraction. Direct language SDK packages and the customer's
original 3.2 GB pack have not been exercised here.

See [first import on macOS](macos-storage-seeds.md) for the implementation's
scope, storage requirements, opt-out and the 100k-file reproduction.
