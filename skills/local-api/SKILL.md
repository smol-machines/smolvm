---
name: local-api
description: "Drives smolvm programmatically over its local HTTP API (smolvm serve) instead of the CLI: create machines, exec and stream commands, move files in and out, and tear them down. Use when building a client, harness, agent tool or MCP backend over smolvm; when a create call is accepted but the machine behaves as if a field was ignored; when a file uploaded over the API has disappeared; when an exec that failed still returned HTTP 200; or when choosing between the Unix socket and loopback TCP. Do not use it as a substitute for the CLI in a shell script, and do not bind the listener beyond loopback: the API has no authentication of any kind."
---

# Driving smolvm over HTTP

Verified on **smolvm v1.14.6** on macOS arm64 and Linux aarch64, 2026-09-10. Done means a machine went through
its whole lifecycle over HTTP and `GET /api/v1/machines` is empty again at the end.

Two rules run through everything here, and both are the same shape: **a 200 is not a result.**

1. **A failing guest command still returns HTTP 200.** Assert `exitCode` from the body.
2. **Upload files only after the workload container is running.** An upload before that returns
   200 with the resolved path and byte count for a file that is then unreadable.

## Procedure

**1. Preflight.**

```bash
scripts/preflight.sh
```

It reports `auth=none`, which is not a warning about your setup: the API has no TLS, token or auth
flag of any kind, so **the transport you pick is the access control**.

**2. Start the server.** A Unix socket is the default here, as it is smolvm's.

```bash
scripts/serve-start.sh
scripts/serve-start.sh --listen 127.0.0.1:8899
```

It waits for `"status":"ok"` from `/health` rather than for the process to exist, records the
listen address and pid for cleanup, and reports any `Reclaimed N dangling VM data dir(es)` line so
you do not later read those directories as a leak.

**3. Export the spec before writing a request body.** This is the step that saves the most time.

```bash
smolvm serve openapi -o ./openapi.json
```

The field names are the schema's, not the CLI's flags. `network` not `net`, `memoryMb` not
`memory`, and `cmd` for the workload you would pass after `--`. Unknown fields are accepted with
200 and ignored. `references/api-fields.md` has the full list and what each wrong name costs.

**4. Run the lifecycle.**

```bash
scripts/lifecycle-check.sh
```

Create, start, wait for the workload container to answer with a value, exec, exec a deliberately
failing command and assert its non-zero `exitCode` came back on a 200, stream, round-trip a file,
stop, delete, and assert the machine list is empty:

```
created_state=ok (created)
started_state=ok (running)
workload_ready_after_s=0
workload_ready=ok (yes)
exec_exit_code=ok (0)
exec_stdout=ok
failing_exec_exit_code=ok (3)
stream_lines=ok (3)
stream_exit_event=ok
file_roundtrip=ok (PAYLOAD123)
machines_empty=ok ({"machines":[]})
result=lifecycle_ok
```

**5. Clean up, machines first.**

```bash
scripts/cleanup.sh --purge
```

Order matters: **stopping the server does not stop machines**, it orphans them. The script deletes
recorded machines, then stops the server, then removes the socket.

## The calls, in short

```bash
B=http://127.0.0.1:8899   # or: curl --unix-socket "$SOCK" http://localhost/...

curl $B/health
curl -X POST $B/api/v1/machines -H 'content-type: application/json' \
  -d '{"name":"m","image":"python:3.12-alpine","network":true,"memoryMb":2048,
       "cmd":["sh","-c","while true; do sleep 3600; done"]}'
curl -X POST $B/api/v1/machines/m/start -H 'content-type: application/json' -d '{}'
curl -X POST $B/api/v1/machines/m/exec  -H 'content-type: application/json' \
  -d '{"command":["sh","-c","echo hi"]}'
curl -N -X POST $B/api/v1/machines/m/exec/stream -H 'content-type: application/json' \
  -d '{"command":["sh","-c","for i in 1 2 3; do echo line$i; sleep 1; done"]}'
curl -X PUT "$B/api/v1/machines/m/files/%2Ftmp%2Fabs.txt" --data-binary 'PAYLOAD'
curl        "$B/api/v1/machines/m/files/%2Ftmp%2Fabs.txt"
curl -X POST   $B/api/v1/machines/m/stop -H 'content-type: application/json' -d '{}'
curl -X DELETE $B/api/v1/machines/m
```

Paths in the `files` route are **absolute and URL-encoded**. `exec` returns stdout as text and as
base64; `exec/stream` emits one `event: stdout` per line then a terminal `event: exit`.

## Traps

Full detail in `references/traps.md` and `references/api-fields.md`.

- **Upload after the container is up, never before.** Reproduced on Linux aarch64: the PUT
  returned `200 {"path":"/tmp/r1.txt","size":6}` and the file was never readable, first with
  `failed to canonicalize target`, then with `failed to read /tmp/r1.txt in the workload
  container`. Both directions pick a namespace per request, and `/tmp` is a path the container
  mounts over. The same sequence on macOS returned the payload, which makes this timing dependent
  rather than safe.
- **A failing guest command is HTTP 200.**
- **Unknown create fields are accepted and ignored**, while a Smolfile rejects them. A `net` for
  `network` was caught at create here with a clear 400 about the missing network, but a `memory`
  for `memoryMb` gets no diagnostic at all: you silently get the default.
- **Killing the server orphans machines.**
- **The spec's `info.version` is not the binary's.** It says `0.5.2` on v1.14.2 while `/health`
  says `1.14.2`. Take the version from `/health`.

## Security defaults, and why they are the defaults

- **The Unix socket is the default because it is the only access control there is.** `serve start`
  has no TLS, certificate, token or auth flag, and the routes it exposes create machines, exec
  arbitrary commands and read and write files. The socket's file permissions are a real boundary;
  a loopback port is a boundary only in the sense that every process on the host is inside it.
- **Loopback TCP is for when you need a URL**, in a container network namespace or for a client
  that cannot do Unix sockets. Treat the port as equivalent to a shell on the host, and do not
  bind anything but `127.0.0.1`.
- **`scripts/serve-start.sh` puts its socket under the packet's own state directory**, not in a
  world-traversable temporary directory, and removes it at cleanup.
- **Machines are deleted before the server is stopped**, because a server shutdown leaves running
  VMs with nothing managing them and no route back to them from the CLI.

## Platform arms

- **macOS arm64** and **Linux aarch64**: the scripts were run here, over the Unix socket.
- **Linux x86_64**: verified in the material behind this packet, over both transports, not re-run
  here.
- **Windows x86_64**: `references/windows.md`, **re-run on 2026-09-11 against v1.14.6** on
  Windows 11 Home build 10.0.26200.0 UBR 9445, where the whole lifecycle passed over loopback TCP.
  No Unix socket form has ever been attempted there, **400 and 404 still return empty bodies**, and
  two shapes fail before reaching a machine: routes live under `/api/v1/`, and a bodiless POST to
  `start` or `stop` needs `application/json` with an empty JSON body.

## Eval prompts, and what they produced

Run on 2026-09-07 PT against v1.14.2 from the published release, under an isolated `HOME`. Output
is verbatim.

**1. "Write me something that drives a smolvm machine over HTTP end to end and proves it worked."**

`scripts/lifecycle-check.sh`, over a Unix socket. All eleven checks passed on macOS 26.6.2 arm64
and on Lima `linux-kvm` (Ubuntu 24.04 aarch64), the Linux one twice in a row. Output as shown in
step 4 above, including `failing_exec_exit_code=ok (3)`, which is the assertion that catches a
guest failure hiding behind a 200.

**2. "I uploaded a file right after starting the machine and now the API says it does not
exist."**

Reproduced on Linux aarch64 by doing exactly that:

```
PUT: {"path":"/tmp/r1.txt","size":6}
GET now: {"error":"agent operation failed: read file: failed to canonicalize target
          /tmp/r1.txt: No such file or directory (os error 2)","code":"INTERNAL_ERROR"}
GET after 30s: {"error":"agent operation failed: read file: failed to read /tmp/r1.txt in
          the workload container: open /tmp/r1.txt: No such file or directory (os error 2)",
          "code":"INTERNAL_ERROR"}
```

The upload reported success for a file that was never readable. The same sequence on macOS arm64
returned `ROUND1` both immediately and after 30 s, so a run that works proves nothing.

**3. "My create call returned 200 but the machine has the wrong settings."**

Verified on both hosts: a body carrying an unknown field is accepted and the field is dropped.

```
POST {"name":"...","image":"alpine","network":true,"memoryMb":2048,"bogusField":1}
-> 200 {"name":"...","state":"created","network":true,"memoryMb":2048,...}
```

and the runbook's `net`/`memory` shape was caught at create on both hosts, with a message that
names the remedy:

```
400 {"error":"config operation failed: create machine: image 'alpine' must be pulled from a
registry, but this machine has no network, so the pull can never succeed. Add --net ...",
"code":"BAD_REQUEST"}
```

A 404 on either host returns `{"error":"machine 'nope-does-not-exist' not found",
"code":"NOT_FOUND"}`, which is the diagnostic Windows does not give you.

## Re-verified on v1.14.6

Run 2026-09-10 PT against v1.14.6 on macOS 26.6.2 arm64 and Lima `linux-kvm` (Ubuntu 24.04
aarch64), over the Unix socket. **All eleven checks green on both**, including
`failing_exec_exit_code=ok (3)`, the case that proves a guest failure arrives on an HTTP 200.

## What was not run

- **The Unix socket form on Windows.** The 2026-09-11 v1.14.6 re-run there used loopback TCP, as
  every Windows run has.
- **Linux x86_64.**
- **Loopback TCP.** `serve-start.sh` accepts `--listen 127.0.0.1:8899` and the code path is the
  same, but every run here used the Unix socket.
- **Authenticated or TLS deployment.** There is no such thing to test: `serve start` has no flags
  for it.
- **The pool and rollout-executor routes** in the spec. They belong to the branch-pool feature.

## Related packets

- `install` for the boot this assumes, `teardown` for the cleanup script.
- `dev-env` for the same lifecycle through the CLI, and for the workload-container behaviour that
  the `cmd` field addresses here.
