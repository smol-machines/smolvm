# Checkpoint format

This document specifies the smolvm checkpoint format: the file a machine's
live state is saved to, the directory form a checkpoint store keeps, and the
lineage every checkpoint records. It is written so that another program can
read, verify and produce checkpoints without reading smolvm's source.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

| | |
|---|---|
| Checkpoint versions | `4` (one generation), `5` (a file carrying its history) |
| Store index version | `1` |
| Container version | pack footer version `1` (readers accept `1`–`3`) |
| File extension | `.checkpoint` (`.smolcheckpoint` is accepted as an earlier name) |
| Reference implementation | [smolvm](https://github.com/smol-machines/smolvm): `src/portable_checkpoint.rs`, `crates/smolvm-checkpoint`, `crates/smolvm-pack` (Apache-2.0) |

## 1. Overview

A checkpoint is a machine paused at one moment: guest RAM, vCPU and device
state, the guest memory layout, and the machine's disks, captured at the same
pause. Every checkpoint also records **lineage**: a unique id, the machine it
came from, and its **parent**, the checkpoint that machine was last captured to
or restored from.

A checkpoint takes one of three forms:

| Form | What it is | Version |
|---|---|---|
| **Checkpoint file** | One file holding one generation | 4, `payload: "assets"` |
| **History file** | One file holding a generation and its retained ancestors | 5, `payload: "chunked"` |
| **Stored checkpoint** | A directory in a checkpoint store: an index, content-addressed objects, retained ancestors | index version 1, embedding a version 4 manifest |

Both files use the same container (section 3). A history file's payload is a
stored checkpoint directory, so sections 7 and 8 apply to it once unpacked.

Readers MUST NOT rely on the file name or extension to decide what a file is.
The manifest decides (section 5).

## 2. Conventions

- Integers in binary structures are unsigned little-endian.
- JSON is UTF-8. Field names are the ones listed here, exactly (snake_case).
- Hashes are lowercase hexadecimal. `sha256` is SHA-256 (FIPS 180-4).
- A **generation id** is 32 lowercase hex characters (128 random bits). It has
  no content meaning.
- Timestamps are RFC 3339 in UTC at whole-second precision, for example
  `2026-09-22T10:12:03Z`.

## 3. File container

A checkpoint file or history file is laid out as:

```text
offset 0            A                  A+M                A+M+64
       | payload    | manifest         | footer           |
       | A bytes    | M bytes, JSON    | 64 bytes         |
```

`A` is `assets_size` and `M` is `manifest_size` from the footer.

### 3.1 Footer

The last 64 bytes of the file:

| Offset | Size | Field | Value in a checkpoint |
|---|---|---|---|
| 0 | 8 | magic | ASCII `SMOLPACK` (`53 4D 4F 4C 50 41 43 4B`) |
| 8 | 4 | version | `1` |
| 12 | 8 | stub_size | `0` |
| 20 | 8 | assets_offset | `0` |
| 28 | 8 | assets_size | `A`, the payload length |
| 36 | 8 | manifest_offset | `A` |
| 44 | 8 | manifest_size | `M`, the manifest length |
| 52 | 4 | checksum | CRC-32 (section 3.2) |
| 56 | 8 | reserved | writers MUST write zeros; readers MUST ignore |

A checkpoint MUST have exactly this layout: `stub_size = 0`,
`assets_offset = 0`, `manifest_offset = assets_size`, and a file length of
exactly `A + M + 64`. Readers MUST reject a checkpoint with bytes between the
manifest and the footer or after the footer. This makes every byte except the
footer part of the checksum. `M` MUST NOT exceed 16 MiB.

The same container carries `.smolmachine` packs, which may use other layouts;
those rules are not part of this specification.

### 3.2 Checksum

`checksum` is CRC-32 with the IEEE 802.3 polynomial (as in zlib and
`crc32fast`) over bytes `[0, A + M)`: the payload and the manifest.

A reader MUST, in this order:

1. Read the footer, check the magic and a version of `1`, `2` or `3`, and check
   the bounds above.
2. Compute the checksum over `[0, A + M)` and compare it with the footer.
3. Only then parse the manifest or read the payload.

A reader SHOULD read the file through one open handle and SHOULD refuse the
file if it changed while being verified. smolvm compares device, inode, length,
modification time and change time before and after.

The checksum detects corruption. It does not authenticate anything; see
section 10.

### 3.3 Payload

The payload is a single zstd stream containing a tar archive. Writers use
level 3; readers MUST accept any valid zstd stream. Readers MUST decompress only
the first `A` bytes of the file.

Tar entries use the GNU format. Guest RAM (`checkpoint/memory.bin`) and raw
disks MAY be GNU sparse entries (type `S`), whose `realsize` is the logical
length; holes read as zeros. Writers sort entries by top-level name.

Readers MUST unpack into a fresh directory and MUST reject any entry whose path,
after resolving `..`, leaves that directory, and any symlink or hard link whose
target does. Readers MUST NOT create device nodes or FIFOs. smolvm also bounds
an unpack to 2,000,000 entries and 128 GiB of declared size.

## 4. Manifest

The manifest is a JSON object: the pack manifest. A file is a checkpoint if and
only if its manifest has a `checkpoint` object. Readers MUST ignore fields they
do not know, in every object in this section.

### 4.1 Pack manifest fields

These fields describe the machine the checkpoint was captured from. A reader of
checkpoints needs only `platform`, `secret_refs` and `checkpoint`.

| Field | Type | Meaning |
|---|---|---|
| `mode` | `"container"` \| `"vm"` | `"vm"` for a checkpoint |
| `image` | string | `vm://<machine name>` for a checkpoint |
| `digest` | string | `"none"` for a checkpoint |
| `platform` | string | Guest platform, for example `linux/arm64`. Its architecture MUST match the restoring host's |
| `host_platform` | string | Platform of the capturing host |
| `cpus`, `mem` | integer | vCPUs and MiB, as configured |
| `entrypoint`, `cmd`, `env` | string arrays | Optional |
| `workdir`, `user` | string | Optional |
| `secret_refs` | object | Optional. A checkpoint MUST NOT carry any; see section 10 |
| `created`, `smolvm_version` | string | Informational |
| `assets` | object | Inventory of runtime files in the payload (section 6) |
| `checkpoint` | object | The checkpoint manifest (section 4.2) |

### 4.2 `checkpoint` object

| Field | Type | Required | Meaning |
|---|---|---|---|
| `version` | integer | yes | `4` for `payload: "assets"`, `5` for `payload: "chunked"` |
| `runtime_abi` | string | yes | `"libkrun-portable-snapshot-v1"` |
| `host_platform` | string | yes | Capturing host: `darwin/arm64`, `linux/amd64`, `linux/arm64`, `windows/amd64` |
| `cpu_contract` | object | yes | Section 4.4 |
| `cpus` | integer | yes | vCPU count, at least 1 |
| `memory_mib` | integer | yes | Guest RAM in MiB, at least 1 |
| `storage_gib` | integer | no | Storage disk size |
| `overlay_gib` | integer | no | Overlay disk size |
| `device_profile` | string | yes | `"smolvm-packed-layers-v1"` when `packed_layers` is present, otherwise `"smolvm-basic-v1"` |
| `state` | asset | yes | vCPU and device state |
| `memory` | asset | yes | Guest RAM |
| `layout` | asset | yes | Guest physical memory layout |
| `disks` | array | yes | Section 4.5 |
| `workload` | object | no | Section 4.6. Absent for machines without an image |
| `network` | object | yes | Section 4.7 |
| `packed_layers` | object | no | Section 4.8 |
| `lineage` | object | no | Section 4.3. Absent only on checkpoints written before lineage existed |
| `payload` | `"assets"` \| `"chunked"` | no | Default `"assets"` |
| `history` | array | no | Only with `payload: "chunked"`. Section 8.2 |
| `credential_ca` | asset | no | The machine's credential CA. Section 10 |

An **asset** is `{ "path": string, "size": integer, "sha256": string }`.
`path` is relative to the payload root, `size` is the uncompressed length, and
`sha256` is the hash of the file's bytes. `sha256` is empty (`""`) for
`memory` and every disk file, whose integrity rests on the container checksum
or, in a store, on per-object hashes.

### 4.3 `lineage`

| Field | Type | Meaning |
|---|---|---|
| `id` | string | Generation id (32 hex) |
| `parent` | string | Optional. The parent's generation id |
| `machine` | string | Name of the machine it was captured from |
| `created_at` | string | Capture time |

### 4.4 `cpu_contract`

A tagged object; `kind` selects the variant.

| `kind` | Other fields | A host is compatible when |
|---|---|---|
| `linux-kvm-intel-portable-v1` | none | It is an Intel (`GenuineIntel`) Linux KVM host |
| `aarch64-features-v1` | `features`: sorted array of `FEAT_*` names | It has every listed feature (a superset is fine) |
| `exact-v1` | `fingerprint`: SHA-256 hex of the host CPU identity | Its fingerprint is identical |

### 4.5 `disks`

Exactly two chains, in order: `role: "storage"`, then `role: "overlay"`. Each
is `{ "role": string, "files": [...] }`, with files ordered from the disk the
machine attaches (index 0) down to its base. Each file is:

| Field | Type | Meaning |
|---|---|---|
| `asset` | asset | Path `checkpoint/disks/<role>/<index>` |
| `target` | string | Name the file is installed as: `<role>.raw` or `<role>.qcow2` at index 0, `.smolcheckpoint-<role>-<index>.<format>` below it |
| `format` | `"raw"` \| `"qcow2"` | A `raw` file MUST be the last in its chain |

Each qcow2 file's backing file name MUST be the next file's `target`. A chain
has at most 64 files. The `.smolcheckpoint-` prefix in `target` is part of the
format and is unaffected by the file extension.

### 4.6 `workload`

| Field | Type | Meaning |
|---|---|---|
| `image` | string | Image reference, non-empty |
| `user` | string | Optional |
| `overlay_owner` | string | Machine that owns the overlay; a valid machine name |
| `restart_policy` | string | `never`, `always`, `on-failure` or `unless-stopped` |
| `restart_max_retries` | integer | 0 means unlimited |
| `restart_max_backoff_secs` | integer | 0 means the runtime default |

### 4.7 `network`

| Field | Type | Meaning |
|---|---|---|
| `enabled` | boolean | Outbound networking |
| `backend` | `"tsi"` \| `"virtio-net"` | Optional |
| `ports` | array of `{ "host", "guest" }` | Optional. Non-zero, unique host ports; requires `virtio-net` |
| `allowed_cidrs`, `dns_filter_hosts` | string arrays | Optional egress policy |
| `guest_subnet` | string | Optional |
| `credential_policy` | object | Optional. Section 10 |
| `credential_placeholders` | object | Optional. Environment variable name to placeholder value; not secret |

`dns` and `network_name` are defined but a capture never writes them: machines
with custom DNS or named networks cannot be checkpointed.

### 4.8 `packed_layers`

Present when the machine mounted its image layers from a `.smolmachine` pack:
`artifact_sha256` (hex, no prefix), `footer_checksum` (that pack's CRC-32) and
an optional `registry_ref`. The pack is not inside the checkpoint; a restoring
host MUST already have it, verified by digest and checksum.

### 4.9 Example

```json
{
  "mode": "vm",
  "image": "vm://worker",
  "digest": "none",
  "platform": "linux/arm64",
  "host_platform": "darwin/arm64",
  "cpus": 2,
  "mem": 1024,
  "assets": { "...": "runtime inventory, section 6" },
  "checkpoint": {
    "version": 4,
    "runtime_abi": "libkrun-portable-snapshot-v1",
    "host_platform": "darwin/arm64",
    "cpu_contract": { "kind": "aarch64-features-v1", "features": ["FEAT_AES", "FEAT_SHA256"] },
    "cpus": 2,
    "memory_mib": 1024,
    "storage_gib": 20,
    "overlay_gib": 10,
    "device_profile": "smolvm-basic-v1",
    "state":  { "path": "checkpoint/checkpoint.bin", "size": 123456, "sha256": "9b1c…" },
    "memory": { "path": "checkpoint/memory.bin", "size": 1073741824, "sha256": "" },
    "layout": { "path": "checkpoint/manifest.bin", "size": 512, "sha256": "4e07…" },
    "disks": [
      { "role": "storage", "files": [
        { "asset": { "path": "checkpoint/disks/storage/0", "size": 21474836480, "sha256": "" },
          "target": "storage.raw", "format": "raw" } ] },
      { "role": "overlay", "files": [
        { "asset": { "path": "checkpoint/disks/overlay/0", "size": 196608, "sha256": "" },
          "target": "overlay.qcow2", "format": "qcow2" },
        { "asset": { "path": "checkpoint/disks/overlay/1", "size": 10737418240, "sha256": "" },
          "target": ".smolcheckpoint-overlay-1.raw", "format": "raw" } ] }
    ],
    "workload": { "image": "alpine:3.20", "overlay_owner": "worker", "restart_policy": "never",
                  "restart_max_retries": 0, "restart_max_backoff_secs": 0 },
    "network": { "enabled": true, "backend": "tsi" },
    "lineage": { "id": "9f2c1a7b3e4d5f60718293a4b5c6d7e8", "parent": "51e0d8c2a9b4c3d2e1f0a9b8c7d6e5f4",
                 "machine": "worker", "created_at": "2026-09-22T10:12:03Z" },
    "payload": "assets"
  }
}
```

## 5. Identifying and opening a checkpoint

1. If the path is a directory containing `checkpoint.json`, it is a stored
   checkpoint (section 7).
2. Otherwise verify the file (section 3.2) and parse the manifest. If it has no
   `checkpoint` object, it is not a checkpoint.
3. Enforce the exact layout (section 3.1) and the compatibility rules
   (section 9).
4. `payload: "assets"`: the payload is described in section 6.
   `payload: "chunked"`: unpack the payload into a fresh directory; it MUST
   contain `checkpoint.json`, and from then on it is a stored checkpoint.

## 6. Assets payload (version 4)

The tar contains:

| Path | Content |
|---|---|
| `checkpoint/checkpoint.bin` | vCPU and device state (`state`), 1 byte to 64 MiB |
| `checkpoint/memory.bin` | Guest RAM (`memory`), a regular or sparse entry |
| `checkpoint/manifest.bin` | Guest memory layout (`layout`), 1 byte to 1 MiB |
| `checkpoint/disks/<role>/<index>` | Disk files (section 4.5), regular or sparse |
| `checkpoint/credential-ca.json` | Optional credential CA, at most 64 KiB |
| `lib/…` | The host hypervisor libraries the state was captured with |
| `agent-rootfs.tar`, `storage.ext4` | The guest agent root filesystem and storage template |

`state`, `memory` and `layout` MUST be at exactly those paths. After unpacking,
every asset's length MUST equal its `size`, and every non-empty `sha256` MUST
match. `state`, `layout` and `credential_ca` MUST have a non-empty `sha256`.
`memory.size` MUST be at most `memory_mib` MiB plus 2 GiB (plus the packed-layer
window when `packed_layers` is present).

The state and memory encodings are defined by the hypervisor library named in
`runtime_abi` and are opaque to this specification: a reader restores them with
a library implementing that ABI.

## 7. Stored checkpoint

A stored checkpoint is a directory, conventionally named `<name>.checkpoint`:

```text
<name>.checkpoint/
  checkpoint.json              index of this generation
  objects/<sha256>             every object any index here references
  generations/<id>/checkpoint.json   index of each retained ancestor
```

A stored checkpoint is self-contained: it holds (as hard links in a store, or
copies) every object it and its retained generations reference, so it restores
without the store or any other checkpoint.

### 7.1 Index (`checkpoint.json`)

Readers MUST reject unknown fields in the index and its file entries.

| Field | Type | Meaning |
|---|---|---|
| `version` | integer | `1` |
| `chunk_size` | integer | `1048576` |
| `manifest` | object | The pack manifest (section 4), with `checkpoint` present |
| `files` | array | The generation's files |

Each entry of `files`:

| Field | Type | Meaning |
|---|---|---|
| `path` | string | Relative path: normal components only, no `..`, not absolute, not empty, unique in the index |
| `size` | integer | Logical length in bytes |
| `mode` | integer | Permission bits; only `0o777` may be set |
| `chunks` | array | One entry per chunk, in order: an object hash, or `null` for a chunk of zeros |

`chunks` MUST have exactly `ceil(size / chunk_size)` entries. No directories,
owners or timestamps are recorded; parent directories are implied by paths.

### 7.2 Chunks and objects

Files are split into fixed 1 MiB chunks. Chunk `i` covers bytes
`[i × 1 MiB, min(size, (i + 1) × 1 MiB))`; the last chunk is its real, shorter
length. A chunk of all zeros, or a range with no data in a sparse file, is
`null` and is not stored.

An object is one chunk:

- Its name is the SHA-256 of the **uncompressed** chunk, 64 lowercase hex.
- Its content is one zstd frame of the chunk (writers use level 3), non-empty
  and at most 1 MiB + 128 KiB.

A reader MUST decompress an object to exactly the chunk's expected length
(decoding with a window of at most 2^23 bytes) and MUST check its SHA-256
against its name before using it. A reader restoring a file sets its length
to `size` and writes each non-null chunk; `null` chunks read as zeros.

## 8. Lineage and history

### 8.1 Parents

- A capture records a fresh `id` and, as `parent`, the checkpoint the machine
  was last captured to or restored from.
- A machine restored from a checkpoint records that checkpoint's id as its
  position, so its next capture names it as `parent`. Restoring an earlier
  checkpoint and capturing again therefore branches the history; nothing is
  overwritten.
- Machines branched from a running machine inherit its position.

### 8.2 Retained generations

A stored checkpoint MAY retain earlier generations under
`generations/<id>/checkpoint.json`, each a verbatim index whose own
`lineage.id` MUST equal `<id>`; entries that don't match are ignored. smolvm
retains up to 32 generations by default, counting the parent itself, and never
more than 256.

A checkpoint's **history** is:

1. its own generation (`~0`),
2. then its ancestors, following `parent` through the retained indexes
   (`~1`, `~2`, …),
3. then any retained generations not on that chain, newest `created_at` first.

A history file's manifest repeats this list as `checkpoint.history`, own
generation first. Each entry is the four `lineage` fields plus `data_bytes`,
the bytes of real data (non-null chunks) in that generation. `history` is
descriptive; readers resolve generations from `generations/`.

### 8.3 Selecting a generation

A generation is selected with:

- `~N`: the Nth entry of the history (`~0` is the checkpoint itself);
- an id prefix of at least 8 hex characters, case-insensitive, which MUST match
  exactly one generation.

A checkpoint file (version 4) holds one generation: only `~0` selects it.

### 8.4 Store lineage records

A checkpoint store keeps `lineage/<id>.json` for every checkpoint published
into it: `id`, `parent`, `machine`, `created_at`, and `path` (the published
directory). These records let a later capture find its parent's directory; they
are a store index, not part of any checkpoint.

## 9. Versioning and compatibility

A reader MUST refuse a checkpoint unless all of these hold:

| Check | Rule |
|---|---|
| Version | `version` is exactly `4` with `payload: "assets"`, or exactly `5` with `payload: "chunked"` |
| Runtime ABI | `runtime_abi` is `libkrun-portable-snapshot-v1` |
| Host | `host_platform` equals the restoring host's, exactly |
| Guest | `platform`'s architecture matches the restoring host's |
| Device profile | Matches whether `packed_layers` is present |
| CPU | `cpu_contract` accepts the restoring host (section 4.4) |
| Network | `network` present; ports valid; `enabled` true if ports or a backend are set |
| Workload | If present: non-empty `image`, valid `overlay_owner`, known `restart_policy` |
| Sizes | `cpus` and `memory_mib` non-zero; asset sizes within section 6's limits |
| Disks | Exactly the chains described in section 4.5 |

Versions evolve as follows:

- Adding an optional field is not a version change. Readers ignore unknown
  manifest fields, so older readers keep working.
- A change an older reader would misread gets a new `version`. Readers accept
  only the versions they implement and refuse others with a clear message,
  never a best-effort read.
- Version 5 exists so readers that predate history refuse history files
  instead of misreading them.

A checkpoint is portable between hosts of the same platform whose CPUs satisfy
its contract. It is not portable across operating systems or architectures.

## 10. Security considerations

- **Integrity is not authenticity.** CRC-32 and per-object SHA-256 detect
  corruption, not tampering, and checkpoints are not signed. Establish where a
  checkpoint came from before restoring it, as you would for any executable
  artifact: restoring runs its guest state.
- **A checkpoint can hold a private key.** When `credential_ca` is present, the
  file carries the machine's credential CA **including its private key**.
  Treat such a checkpoint as a secret.
- **No secrets travel.** Captures refuse machines with secret references, and a
  restore refuses any checkpoint whose manifest has `secret_refs`. Credential
  bindings travel only as names, hosts and placeholders; values are supplied by
  the restoring host.
- **Credential policy is untrusted input.** A restore re-validates
  `network.credential_policy` with the same rules machine creation uses.
- **Host-bound state is never captured.** A capture refuses machines with host
  mounts, published sockets, remote volumes, secret references, host-backed
  image layers, custom DNS, named inter-machine networks, GPU (Vulkan or CUDA)
  state, Rosetta, SSH agent forwarding or Docker socket forwarding.
- **Unpacking is hostile-input handling.** Section 3.3's path and link rules
  apply to every payload, including history files.

## 11. Limits

| Item | Limit |
|---|---|
| Manifest | 16 MiB |
| Payload unpack | 2,000,000 entries, 128 GiB declared size |
| `state` / `layout` | 64 MiB / 1 MiB |
| `credential_ca` | 64 KiB |
| Disk chain | 64 files |
| Index file | 256 MiB |
| Files per index | 100,000 |
| Bytes per generation | 2 TiB |
| Object | 1 MiB + 128 KiB compressed; 1 MiB uncompressed |
| Retained generations | 256 (default 32) |

## 12. Writing checkpoints

A writer that wants smolvm's durability guarantees:

- Writes each object to a temporary file in the same directory, flushes it, and
  renames it into place without replacing an existing name.
- Writes `checkpoint.json` with create-new semantics and flushes it, retained
  generation indexes included, then flushes the directories that name them.
- Publishes a checkpoint by renaming its staging directory or file into place
  with no-replace semantics (`renameat2(RENAME_NOREPLACE)` on Linux,
  `renamex_np(RENAME_EXCL)` on macOS). An existing checkpoint is never
  overwritten, and a failed capture leaves nothing at the output path.
- Names a new file `<name>.checkpoint`.

## 13. Conformance

The reference implementation's tests, run from a smolvm checkout, pin the rules above, including:
exact-version refusal, checksum-before-parse, the exact container layout,
history resolution (`~N`, id prefixes, ambiguity), unpack path safety, and
restoring every generation from a single history file after the directories it
came from are deleted. Run them with:

```sh
cargo test -p smolvm-checkpoint
cargo test -p smolvm-pack --lib
cargo test --lib portable_checkpoint
```
