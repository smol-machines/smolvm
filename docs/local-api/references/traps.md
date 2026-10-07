# Local API traps

## Upload files only after the workload container is running

**This is the one ordering rule in this packet, and it applies on every platform.**

A file uploaded before the workload container is up is written into the agent's own namespace.
Once the container starts, reads resolve **inside the container**, and for a path the container
mounts over, the earlier file is no longer in the view being read. `/tmp` is exactly such a path:
it is a tmpfs inside the guest, so the container's own `/tmp` masks whatever was seeded underneath.

Both directions pick a namespace per request. `handle_file_write` and
`handle_streaming_file_read` each switch on `nsfile::GuestNs::for_workload()`
(`crates/smolvm-agent/src/main.rs` at v1.14.2), writing and reading inside the workload container
when one is running and in the agent's namespace otherwise. The source's own comment claims the
pre-container write is safe, "seeding it before the container starts is exactly how the file
becomes visible once it does". **That holds for overlay paths and not for paths the container
mounts over.**

Reproduced on Ubuntu 24.04 aarch64 on 2026-09-07, PUT immediately after `POST /start`:

```
PUT  files/tmp%2Fr1.txt   ->  200 {"path":"/tmp/r1.txt","size":6}
GET  files/tmp%2Fr1.txt   ->  500 failed to canonicalize target /tmp/r1.txt: No such file or directory
GET  again after 30 s     ->  500 failed to read /tmp/r1.txt in the workload container: ...
```

The upload reported success, with the resolved path and the byte count, for a file that was never
readable. The two different error texts are the two namespaces: before the container it cannot
canonicalize the path at all, after it the read happens inside the container and misses.

**It is timing dependent, which makes it worse rather than better.** The same sequence on macOS
arm64, and on Linux with a long-lived `cmd` in the create body, returned `ROUND1` both immediately
and after 30 s. A run that happens to work proves nothing about the next one.

**Measured again on v1.18.2, 2026-09-24**, after it had not reproduced on v1.16.1: on Lima
`linux-kvm` (Ubuntu 24.04 aarch64) the same PUT returned the same 200, the immediate GET the same
`failed to canonicalize target /tmp/r1.txt`, and the GET 20 s later the same `failed to read
/tmp/r1.txt in the workload container`. macOS arm64 read `ROUND1` both times. On v1.22.2 it did
not reproduce, 0 of 3 on each host.

**So:** wait for a successful `exec` before uploading anything, which is what
`scripts/lifecycle-check.sh` does, or upload to a path on the overlay such as `/root` rather than
one the container mounts over.

## A failing guest command is still HTTP 200

Check `exitCode` in the body. `scripts/lifecycle-check.sh` deliberately runs `sh -c 'exit 3'` and
asserts `exitCode == 3`, so the assertion that catches this is itself tested.

## Stopping the server leaves its machines running

On shutdown it prints `Shutting down server (VMs continue running)...`, and that is the only
notice you get, in a line you will miss if stderr is redirected. **Delete machines before stopping
the server**, or they keep running after it. `scripts/cleanup.sh` does them in that order.

## `serve start` also reclaims stale VM directories

On startup it printed `Reclaimed 2 dangling VM data dir(es)`, which is what clears the small
leftover directories a crashed or force-killed run leaves in the cache. Worth knowing before
reporting those as a leak.

## The default listen address is derived, not hard-coded

On Linux it is `smolvm.sock` under `XDG_RUNTIME_DIR` when that is set
(`unix:///run/user/<uid>/smolvm.sock`) and `/tmp/smolvm.sock` otherwise; macOS always gets
`/tmp/smolvm.sock`, and Windows `127.0.0.1:8080`. The help prints the value for the user who ran it.

## `serve openapi` writes to stdout by default

Pass `-o`, or you will paste a 150 KB spec into your terminal. On Windows it writes its
confirmation to stderr, which PowerShell renders as an error record even though the file is
written and the exit code is 0.

## A plain server has no authentication of any kind

`serve start` exposes create, exec and file routes, and started plainly it has no TLS, token or
auth. On loopback that is a single-user boundary; the Unix socket, whose file permissions are the
boundary, is the safer default and is why it is smolvm's default and this packet's.

**Mutual TLS is configured from the environment, not by a flag.** With `SMOLVM_SERVE_TLS_CERT`,
`SMOLVM_SERVE_TLS_KEY` and `SMOLVM_SERVE_TLS_CLIENT_CA` set, measured on macOS arm64 on v1.22.2: a
client with no certificate was refused during the handshake, one signed by the client CA got
`{"status":"ok","version":"1.22.2",...}` from `/health`, and with `--mtls-client-cn` set to another
name the same certificate was refused. The server warns that without `--mtls-client-cn` any
certificate the CA signed has full access. **It also opens a plain listener beside the TLS one**,
`smolvm local API (loopback, plain) on http://127.0.0.1:<port + 1>` (`SMOLVM_SERVE_LOCAL_ADDR`
moves it, to a loopback address only). It has no authentication and answers only `/health`,
`/readyz`, `/capacity` and `/metrics`; the machine, exec and file routes are on the TLS port. Only
`/health` was requested here.

## Only one server per host, unless you move its rollout port

Every `serve start` binds `127.0.0.1:10081` for the branch-pool rollout routes, whatever `--listen`
says, so a second server on the same host exits at once:

```
Error: config operation failed: bind guest rollout ingress: 127.0.0.1:10081: Address already in use (os error 48)
```

Measured on macOS arm64 on v1.22.2 with another server already holding the port. With
`SMOLVM_GUEST_ROLLOUT_HOST_PORT=10091` the second server started and answered on `/health`.

## Field names, versions and error bodies

Those have their own page: `references/api-fields.md`. The short version is that unknown fields
are refused with `422` from v1.22.2 and were accepted with 200 and ignored before it, `network`
and `memoryMb` are not `net` and `memory`, and the version in the exported spec is not the
binary's.
