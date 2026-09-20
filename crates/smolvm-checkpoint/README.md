# smolvm-checkpoint

Use SmolVM's incremental checkpoint storage from Rust without linking the VM
runtime. The crate stores stable files or streams as verified, content-addressed
chunks, restores independent writable files, and exports standalone artifacts.

Until published to crates.io, use a path dependency on this checkout:

```toml
[dependencies]
smolvm-checkpoint = { path = "../smolvm/crates/smolvm-checkpoint" }
```

Run the complete storage example with:

```sh
cargo run -p smolvm-checkpoint --example roundtrip
```

## Capture and restore

1. Create a private staging directory and a cache on the same filesystem.
2. Create a `Writer`; call `ingest`, `ingest_tree`, or `ingest_memory`.
3. After all source operations succeed, call `finish`, then `publish`.
4. Call `materialize` into a fresh private directory to restore verified files.

Repeated captures reuse unchanged 1 MiB chunks automatically. Each checkpoint
owns hard links to all its objects: deleting the cache or an older checkpoint
does not invalidate later checkpoints. `prune` removes unreferenced cache
objects. Drop active writers before pruning.

Reuse is based on content, not ancestry: sibling checkpoints can share chunks,
but the crate does not record a parent/child VM lineage graph. Each index lists
all objects needed for that checkpoint, rather than requiring an ordered chain
of earlier checkpoints to restore. Machine lineage remains SmolVM's concern.

`materialize_with_base` can reuse a pristine materialization registered with
`promote_base`; unsupported filesystem cloning falls back to full restoration.
`export` produces a standalone portable artifact. Manifest types are available
under `smolvm_checkpoint::format`.

## Boundary and safety

This is the storage layer, not a hypervisor or a live VM client. The caller must
quiesce or snapshot its data before ingestion and supply consistent RAM, disk,
and execution-state files. Live capture, VM compatibility checks, pause/resume,
and branching remain in SmolVM. Arbitrary files plus a manifest do not create a
bootable checkpoint.

Use Linux or macOS for checkpoint storage. Keep caches, staging, and prepared
bases private and immutable once published; they can contain credentials and
application memory. Source files must not change during ingestion. On failure,
discard staging/output directories rather than treating partial work as a
checkpoint. Checksums detect damaged objects; they do not authenticate an
untrusted checkpoint's author.

The extraction preserves SmolVM's existing index and object formats. It does
not make VM state portable across incompatible architectures or runtimes.
