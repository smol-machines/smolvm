# Reading the API's own schema, and the field names that bite

## Contents

- Export the spec first
- The create body's field names are not the CLI's flags
- Unknown fields are refused from v1.22.2, and were silently ignored before it
- Error bodies carry a reason
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
2026-09-07, `"1.14.3"` on 2026-09-08, and `"1.18.2"` against a spec still at `0.5.2` on
2026-09-24. The gap widens with every release, because the spec's
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
(`use --block-io sync`), which is a boot failure mode none of the other packets mention. **v1.18.x adds `credentials`**, the credential substitution bindings the `credentials` packet
covers, **and `guestSubnet`**, the API form of `--guest-subnet`; `from` now takes a
`.smolcheckpoint` as well as a `.smolmachine` and restores its captured state. **The next release adds
`diskDurability`** (`full` or `deferred`, the API form of `--disk-durability`). Unset means `full`,
so leaving it out keeps the behaviour this packet describes. **Export the spec
against your own binary rather than trusting this list**, which is a snapshot of three releases.

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

## Unknown fields are refused from v1.22.2, and were silently ignored before it

**On v1.22.2 an unknown field is a `422` that names it**, measured on macOS arm64 with both of the
names this page warns about:

```
POST /api/v1/machines {"name":"...","image":"alpine","network":true,"memory":1024}
-> 422 Failed to deserialize the JSON body into the target type: memory: unknown field `memory`,
   expected one of `name`, `cpus`, `memoryMb`, `mounts`, `ports`, `network`, ... at line 1 column 63
```

The same with `net` reads `net: unknown field \`net\``. The rest of this section is how releases
before v1.22.2 behave.

Verified on macOS arm64 and Linux aarch64 at v1.14.2: a create body carrying `bogusField` returns
**200** and a machine built from the fields it did recognise.

```
POST /api/v1/machines {"name":"...","image":"alpine","network":true,"memoryMb":2048,"bogusField":1}
-> 200 {"name":"...","state":"created","network":true,"memoryMb":2048,...}
```

On v1.18.2, 2026-09-24, both hosts: a body with `memory` for `memoryMb` came back `200` with
`"memoryMb":8192`, the default.

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

**v1.23.0 no longer returns that 400**
([#1536](https://github.com/smol-machines/smolvm/pull/1536)). On macOS arm64 a create with
`"image":"alpine","network":false` returned 200 `created`, the start returned `running` with the
image fetched on the host, and an exec read `3.24.2` from `/etc/alpine-release`. A machine with no
network is now a valid request, so leaving the network off by mistake shows up only when the
workload fails to reach something; the `net` name itself is still a `422` on v1.23.0.

## Error bodies carry a reason

Observed here at v1.14.2:

```
GET /api/v1/machines/nope-does-not-exist
-> 404 {"error":"machine 'nope-does-not-exist' not found","code":"NOT_FOUND"}
```

On Windows the server sends the same bodies; PowerShell 5.1's `Invoke-WebRequest` showed them as
empty, and `curl.exe` reads them. See `references/windows.md`.

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

`serve start` has no flag that turns TLS on: mutual TLS is configured from the environment. From
v1.22.1 `--mtls-client-cn` limits API access to client certificates with that subject CN, and
`--mtls-allow-peer-blobs` lets the client CA's other certificates reach the peer blob routes only.
`references/traps.md` has what was measured, and no lifecycle was driven over it here. The pool and
rollout-executor routes in the spec belong to the branch-pool feature, not to this use case, and
nothing here exercises them.

There is no checkpoint route in the exported spec, but the server has one:
`POST /api/v1/machines/{id}/checkpoint` captures a running machine and `PUT` on the same path
restores one, and `serve start --help` lists the capture route. The create body's `from` field also
restores a checkpoint. Nothing here exercised either.
