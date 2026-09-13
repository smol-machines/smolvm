# Reading the API's own schema, and the field names that bite

## Contents

- Export the spec first
- The create body's field names are not the CLI's flags
- Unknown fields are accepted and silently ignored
- Error bodies carry a reason on macOS and Linux, and were empty on Windows
- Route parameters are inconsistent in the spec
- Assert `exitCode` from the body, never the HTTP status
- The routes this packet does not cover

## Export the spec first. This is the step that saves the most time.

```bash
smolvm serve openapi -o ./openapi.json
```

`serve openapi` writes to **stdout** by default, so without `-o` you paste a 150 KB spec into your
terminal. Read `components.schemas.CreateMachineRequest` before writing a create body.

**The version in the spec is not the binary's.** The exported spec says `info.version = "0.5.2"`
while `GET /health` on the same server reports the real one: `"1.14.2"` observed on macOS arm64 on
2026-09-07, and `"1.14.3"` on 2026-09-08. The gap widens with every release, because the spec's
number is hardcoded. Take the version from `/health`, never from the spec.

## The create body's field names are not the CLI's flags

`CreateMachineRequest` at v1.14.2 accepts:

```
allowedCidrs  allowedHosts  autoGraph  blobPeers  cmd  cpus  cuda  dockerSocket
entrypoint  env  from  gpu  image  memoryMb  mounts  name  network  networkBackend
overlayGb  ports  registryIdentityToken  registryRef  restart  secrets  storageGb  workdir
```

**v1.14.3 adds `blockIo`**, selecting the block I/O engine, and adds host and guest memory fields
to the responses (`hostMemoryAvailableMb`, `usedMemoryPssMb` and neighbours). `blockIo` defaults to
unset, so leaving it out keeps the behaviour this packet describes. Asking for the async engine on
a host without `io_uring` fails the boot with a message naming the way out
(`use --block-io sync`), which is a boot failure mode none of the other packets mention. **Export
the spec against your own binary rather than trusting this list**, which is a snapshot of two
releases.

The three worth memorising, because the CLI trains you to write the other thing:

| you will write | the schema wants |
|---|---|
| `net` | `network` |
| `memory` | `memoryMb` |
| a workload after `--` | `cmd` (and `entrypoint`) |

**`cmd` matters more than it looks.** Without it the image's own ENTRYPOINT or CMD becomes the
machine's persistent workload, and for an interpreter image such as `python:3.12-alpine` that
command reads EOF and exits at once. The container is then relaunched, and an `exec` that lands in
the gap comes back as `exitCode: 1` with **empty stdout and empty stderr**, which is quieter than
the CLI's equivalent failure. That happened once in this packet's own run on a nested-virt aarch64
host, and `scripts/lifecycle-check.sh` now passes a long-lived `cmd`.

## Unknown fields are accepted and silently ignored

Verified on macOS arm64 and Linux aarch64 at v1.14.2: a create body carrying `bogusField` returns
**200** and a machine built from the fields it did recognise.

```
POST /api/v1/machines {"name":"...","image":"alpine","network":true,"memoryMb":2048,"bogusField":1}
-> 200 {"name":"...","state":"created","network":true,"memoryMb":2048,...}
```

Note the contrast: a **Smolfile rejects unknown keys**, and the README says so. The API does not.

**What the wrong name costs depends on which one you got wrong.** Writing `net` instead of
`network` produces a machine with no networking, and on both hosts here that was caught at create
with a 400 and a good message:

```
{"error":"config operation failed: create machine: image 'alpine' must be pulled from a
registry, but this machine has no network, so the pull can never succeed. Add --net (or
publish a port with -p, or set an egress policy with --allow-cidr/--allow-host). ...",
 "code":"BAD_REQUEST"}
```

A wrong name that does not change network reachability, such as `memory` for `memoryMb`, gets no
diagnostic at all: you simply get the default. So do not rely on the 400 above to catch a typo.

## Error bodies carry a reason on macOS and Linux, and were empty on Windows

Observed here at v1.14.2:

```
GET /api/v1/machines/nope-does-not-exist
-> 404 {"error":"machine 'nope-does-not-exist' not found","code":"NOT_FOUND"}
```

On the Windows host, **400 and 404 returned empty bodies**, which is what turns a wrong field name
into a silent failure there. See `references/windows.md`.

## Route parameters are inconsistent in the spec

Some paths take `{id}` and some take `{name}`, for the same thing:

- `{id}`: `exec`, `exec/stream`, `files/{path}`, `images`, `images/pull`, `logs`, `run`
- `{name}`: the machine itself, `start`, `stop`, `branches`, `fork`, `export`, `resize`, `sync`

Both accept the machine name in practice, but a generated client will expose two different
parameter names for one concept.

## Assert `exitCode` from the body, never the HTTP status

A command that fails inside the guest is still **HTTP 200**:

```
POST .../exec {"command":["sh","-c","exit 3"]}  ->  200 {"exitCode":3,...}
```

`scripts/lifecycle-check.sh` runs exactly that case, so the assertion that catches it is itself
tested rather than assumed.

`exec` returns stdout both as text and base64 (`stdout` and `stdoutB64`), and `exec/stream` emits
one `event: stdout` per line followed by a terminal `event: exit`.

## The routes this packet does not cover

`serve start` has **no TLS, certificate, auth or token flag at all**, so there is no authenticated
deployment to describe. The pool and rollout-executor routes in the spec belong to the branch-pool
feature, not to this use case, and nothing here exercises them.
