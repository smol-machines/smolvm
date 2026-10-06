---
name: local-api
description: "Drives smolvm programmatically over its local HTTP API (smolvm serve) instead of the CLI: create machines, exec and stream commands, move files in and out, and tear them down. Use when building a client, harness, agent tool or MCP backend over smolvm; when a create call is accepted but the machine behaves as if a field was ignored; when a file uploaded over the API has disappeared; when an exec that failed still returned HTTP 200; or when choosing between the Unix socket and loopback TCP. Do not use it as a substitute for the CLI in a shell script, and do not bind a plain listener beyond loopback: a server started without mutual TLS has no authentication of any kind."
---

# Driving smolvm over HTTP

Verified on **smolvm v1.23.0** on macOS arm64, 2026-10-04, and on **v1.18.2** on Linux aarch64, 2026-09-24. Done means a machine went through
its whole lifecycle over HTTP and `GET /api/v1/machines/<name>` answers `NOT_FOUND` at the end.
The Linux runs used the scripts of their date; this version's preflight and cleanup scripts ran
on Linux aarch64 on v1.22.2 on 2026-10-03.

Two rules run through everything here, and both are the same shape: **a 200 is not a result.**

1. **A failing guest command still returns HTTP 200.** Assert `exitCode` from the body.
2. **Upload files only after the workload container is running.** An upload before that returns
   200 with the resolved path and byte count for a file that is then unreadable.

## Procedure

**1. Preflight.**

```bash
scripts/preflight.sh
```

It reports `auth=none_unless_mtls`, which is not a warning about your setup: a server started the
way this packet starts it has no TLS, token or auth of any kind, so **the transport you pick is the
access control**. Mutual TLS exists, configured from the environment rather than by a flag;
`references/traps.md` has what it does and the plain listener it opens beside itself.

**2. Start the server.** A Unix socket is the default here, as it is smolvm's.

```bash
scripts/serve-start.sh
scripts/serve-start.sh --listen 127.0.0.1:8899
```

It waits for `"status":"ok"` from `/health` rather than for the process to exist, records the
listen address and pid for cleanup, and reports any `Reclaimed N dangling VM data dir(es)` line so
you do not later read those directories as a leak. Run again while the recorded server is up, it
prints `result=already_serving` with the recorded address and starts nothing, whatever `--listen`
says.

**3. Export the spec before writing a request body.** This is the step that saves the most time.

```bash
smolvm serve openapi -o ./openapi.json
```

The field names are the schema's, not the CLI's flags. `network` not `net`, `memoryMb` not
`memory`, and `cmd` for the workload you would pass after `--`. From v1.22.2 an unknown field is
refused with `422` and a message that names it; before that it was accepted with 200 and ignored.
`references/api-fields.md` has the full list and what each wrong name cost on older releases.

**4. Run the lifecycle.**

```bash
scripts/lifecycle-check.sh
```

Create, start, wait for the workload container to answer with a value, exec, exec a deliberately
failing command and assert its non-zero `exitCode` came back on a 200, stream, round-trip a file,
stop, delete, and assert the machine is gone:

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
machine_gone=ok (NOT_FOUND)
result=lifecycle_ok
```

**5. Clean up, machines first.**

```bash
scripts/cleanup.sh --purge
```

`cleanup.sh` waits up to 20 seconds, polling the machine list, and prints `waiting=up to 20s`
first: an ephemeral machine's entry retires after its run returns.

Order matters: **stopping the server does not stop machines**, which keep running after it exits.
The script deletes recorded machines, then stops the server, then removes the socket.

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

- **Upload after the container is up, never before.** On Linux aarch64 on v1.14.6 and v1.18.2 the
  PUT returned `200 {"path":"/tmp/r1.txt","size":6}` for a file that was never readable; `/tmp` is
  a path the container mounts over. It did not reproduce on v1.16.1 or v1.22.2, nor ever on macOS.
  Order the upload after a successful `exec`; a run that happens to work proves nothing.
- **A failing guest command is HTTP 200.**
- **Unknown fields are refused from v1.22.2, and were silently dropped before it.** Before v1.22.2
  a `memory` for `memoryMb` got no diagnostic at all and the machine took the default.
- **A second `serve start` on the same host fails** with `bind guest rollout ingress:
  127.0.0.1:10081: Address already in use`, whatever `--listen` says: every server binds that port
  for the branch-pool rollout routes. Set `SMOLVM_GUEST_ROLLOUT_HOST_PORT` to another port for the
  second one.
- **Stopping the server leaves machines running.**
- **The spec's `info.version` is not the binary's.** It says `0.5.2` on v1.14.2 while `/health`
  says `1.14.2`, and still `0.5.2` on v1.22.2. Take the version from `/health`.
- **The default listen path differs per platform, and `--help` shows only one of them.** The help
  prints `[default: unix:///tmp/smolvm.sock]`, and its own example line says
  `unix:///$XDG_RUNTIME_DIR/smolvm.sock`. Observed on v1.16.1: the socket appeared at
  `/tmp/smolvm.sock` on macOS arm64 and at `/run/user/501/smolvm.sock` on Lima aarch64. Read the
  path the server reports rather than assuming either.

## Pausing a machine over the API

v1.18.0 added `POST /api/v1/machines/{name}/pause` and `/resume`. Pause saves RAM, disks and the
running execution and stops the machine; resume brings back that execution under the same name
rather than booting a fresh guest. On macOS before v1.20.0 the machine has to be started
branchable, which over the API is a query parameter on start, and the calls below always do it:

```bash
curl -X POST "$B/api/v1/machines/m/start?branchable=true" -H 'content-type: application/json' -d '{}'
curl -X POST  $B/api/v1/machines/m/pause  -H 'content-type: application/json' -d '{}'   # state: paused
curl -X POST  $B/api/v1/machines/m/resume -H 'content-type: application/json' -d '{}'   # state: running
```

Assert on a value the workload holds in memory, not on the state field. Measured on v1.18.2 on
both hosts, and on macOS again on v1.22.2, with a workload that writes an incrementing counter every second: it read 9 before the
pause, the machine stayed paused for 10 s, and 3 s after the resume it read 13 on macOS and 12 on
Linux, so the process continued from where it stopped, did not restart at 1, and did not run while
paused. Over the CLI a paused machine refuses `stop` and `start`; the `teardown` packet has those
messages, and `branch-and-checkpoint` covers pause alongside checkpoints.

## Security defaults, and why they are the defaults

- **The Unix socket is the default because it is the only access control a plain server has.** A
  server started without the mutual TLS variables has no TLS, certificate, token or auth of any
  kind, and the routes it exposes create machines, exec arbitrary commands and read and write files. The socket's file permissions are a real boundary;
  a loopback port is a boundary only in the sense that every process on the host is inside it.
- **Loopback TCP is for when you need a URL**, in a container network namespace or for a client
  that cannot do Unix sockets. Treat the port as equivalent to a shell on the host, and do not
  bind anything but `127.0.0.1`.
- **`scripts/serve-start.sh` puts its socket under the packet's own state directory**, not in a
  world-traversable temporary directory, and removes it at cleanup.
- **Machines are deleted before the server is stopped**, because stopping the server does not stop
  them: `serve start --help` says machines persist independently of the server, and on shutdown it
  prints `Shutting down server (VMs continue running)...`.

## Platform arms

- **macOS arm64**: v1.23.0, over loopback TCP, and v1.22.2 over the Unix socket as well.
- **Linux aarch64**: v1.18.2 over the Unix socket, 2026-09-24, `result=lifecycle_ok` with all
  eleven checks. The single v1.22.2 run failed only at `machines_empty`, the check that then
  required an empty machine list, on `image-seed-*` helpers an interrupted run had left listed. On
  v1.23.0 the current script passed over the Unix socket, run once.
- **Linux x86_64**: verified on v1.14.2 on an NVIDIA A10 cloud host, over both transports, not
  re-run since.
- **Windows x86_64**: `references/windows.md`, **re-run on 2026-10-03 against v1.22.2** on
  Windows 11 Home build 10.0.26200 UBR 9457, where the whole lifecycle passed over loopback TCP. A `unix://` listen is refused there.
  Error bodies arrive as on Unix, and PowerShell 5.1's `Invoke-WebRequest` drops them, so read
  them with `curl.exe`. Routes live under `/api/v1/`; a bodiless POST to `start` is accepted from
  v1.21.0.

## Eval prompts, and what they produced

**1. "Write me something that drives a smolvm machine over HTTP end to end and proves it worked."**

`scripts/lifecycle-check.sh`. All eleven checks passed on macOS arm64 on v1.22.2, over loopback TCP
and the Unix socket, and on v1.23.0 over loopback TCP on macOS and the Unix socket on Linux, with
the output shown in step 4, including `failing_exec_exit_code=ok (3)`, the assertion that catches a
guest failure hiding behind a 200. The final `machine_gone` check ran over loopback TCP on
2026-10-03 and over the Unix socket on 2026-10-04; the earlier runs ended with `machines_empty`.

**2. "I uploaded a file right after starting the machine and now the API says it does not
exist."**

Reproduced on Linux aarch64 on v1.14.6 and on v1.18.2 by doing exactly that, with the output in
`references/traps.md`; on v1.22.2 it did not reproduce, 0 of 3 on each host.

**3. "My create call returned 200 but the machine has the wrong settings."**

On v1.22.2 a misnamed field is refused before anything is created; before v1.22.2 it was accepted
and dropped, which `references/api-fields.md` records:

```
POST /api/v1/machines {"name":"...","image":"alpine","network":true,"memory":1024}
-> 422 Failed to deserialize the JSON body into the target type: memory: unknown field `memory`,
   expected one of `name`, `cpus`, `memoryMb`, `mounts`, `ports`, `network`, ... at line 1 column 63
```

A 404 returns `{"error":"machine 'nope-does-not-exist' not found","code":"NOT_FOUND"}`.

## Re-verified on v1.23.0

Run 2026-10-04 PT against v1.23.0 from the published release, checksum checked, under a fresh
isolated `HOME` on macOS 27.0.1 arm64, once. On Lima `linux-kvm` (Ubuntu 24.04 aarch64) the
checks named below ran once, so the Linux stamp stays on its earlier release.

macOS: `result=lifecycle_ok` with all eleven checks over loopback TCP, and `serve-start.sh`
`result=serving` on the Unix socket. A `memory` and a `net` field were each refused with `422`, the
expected list now including `nestedVirt` and `autoGraph`; the upload race did not reproduce, 0 of
3; pause and resume over the API brought the counter from 1 before a 10 s pause to 5 three seconds
after the resume. The spec still says `info.version 0.5.2`. A create with `"network":false` and a
registry image returned 200, which `references/api-fields.md` records.

Linux aarch64: `serve-start.sh` on the Unix socket with the server's defaults, which from v1.23.0
include `--seccomp enforce` on arm64 ([#1533](https://github.com/smol-machines/smolvm/pull/1533)),
then `lifecycle-check.sh` `result=lifecycle_ok` through `machine_gone=ok (NOT_FOUND)`.

## Re-verified on v1.22.2

Run 2026-10-03 PT against v1.22.2 from the published release, checksum checked, under an isolated
`HOME` on macOS 27.0.1 arm64, twice, the second time from a fresh `HOME`. On Lima `linux-kvm`
(Ubuntu 24.04 aarch64) guests above 2048 MiB timed out on 2026-10-03, so the Linux lines below are
a single run and the Linux stamp stays on its earlier release.

macOS: `result=lifecycle_ok` over loopback TCP and the Unix socket, a `memory` and a `net` field
each refused with `422`, the upload race 0 of 3, and pause and resume over the API with the counter
at 11 before a 10 s pause and 15 three seconds after the resume. The spec says
`info.version 0.5.2`. Mutual TLS and the second-server port are in `references/traps.md`.

Linux aarch64: both `422` refusals word for word and the upload race 0 of 3. The lifecycle, run
with the script of that date, failed only at `machines_empty`, the check that then required an
empty machine list, on two `image-seed-*` helpers an interrupted run had left in the list.

## What was not run

- **Linux x86_64.**
- **Loopback TCP on Linux.**
- **A client of a mutual TLS server driving the lifecycle.** The handshake was checked on v1.22.2,
  a client without a certificate refused and one with a certificate answered on `/health`, but no
  machine was created over it.
- **The pool and rollout-executor routes** in the spec. They belong to the branch-pool feature.

## Related packets

- `install` for the boot this assumes, `teardown` for the cleanup script.
- `dev-env` for the same lifecycle through the CLI, and for the workload-container behaviour that
  the `cmd` field addresses here.
