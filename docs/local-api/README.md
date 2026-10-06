# Driving smolvm over HTTP

The same machine lifecycle the CLI drives, over a local HTTP API, for a program that has to create,
run and delete machines without shelling out. Two rules run through everything here and they are
the same rule: **a 200 is not a result.**

`SKILL.md` is the procedure, `references/api-fields.md` the field names the spec uses, and
`scripts/lifecycle-check.sh` asserts eleven things end to end.

## Starting the server

```bash
smolvm serve start                                   # a Unix socket, the default
smolvm serve start --listen 127.0.0.1:8080           # loopback TCP instead
smolvm serve openapi -o ./openapi.json               # the field names from your binary
```

The default listen path is derived rather than fixed, and the help's own default line and its
example disagree: on macOS the socket appeared at `/tmp/smolvm.sock` and on Linux at
`/run/user/<uid>/smolvm.sock`. Read the path the server reports rather than assuming either.

**A plain server has no authentication of any kind.** Whoever can reach the socket or the port can
create and run machines, so treat it as equivalent to a shell on the host, and prefer the Unix
socket. Mutual TLS is configured from the environment, and a server started that way still opens a
plain loopback listener beside it; `references/traps.md` has both.

## The endpoints

The HTTP API section of [`AGENTS.md`](../../AGENTS.md#http-api) lists the key endpoints; pause and
resume are added here.

```
POST   /api/v1/machines                    create           GET    /api/v1/machines            list
GET    /api/v1/machines/:name              get              DELETE /api/v1/machines/:name       delete
POST   /api/v1/machines/:name/start        start            POST   /api/v1/machines/:name/stop  stop
POST   /api/v1/machines/:name/exec         exec             POST   /api/v1/machines/:name/exec/stream  exec, SSE
PUT    /api/v1/machines/:name/files/*path  upload           GET    /api/v1/machines/:name/files/*path  download
GET    /api/v1/machines/:name/logs         logs, SSE        POST   /api/v1/machines/:name/images/pull   pull
POST   /api/v1/machines/:name/pause        pause            POST   /api/v1/machines/:name/resume  resume
```

A `GET` on the files route for a directory returns a listing, `{"entries":[{"kind":..., "name":...,
"size":...}]}`. Pause on macOS before v1.20.0 needs a machine started with `?branchable=true` on the start call,
and this packet's pause steps always start it that way.

## A 200 is not a result

- **A guest command that failed still returns HTTP 200.** The body carries `exitCode`; assert that,
  not the status.
- **Unknown fields in a create body are refused with `422` from v1.22.2**, with a message that
  names the field; before it they were accepted and ignored. Export the spec and read the schema
  before writing a body.
- **Upload after the workload container is running, never before.** An upload before it returned
  200 with a resolved path and a byte count for a file that was then unreadable.
- **Stopping the server leaves its machines running.** Delete them first.

`SKILL.md` carries the dates and the hosts for each of those.
