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

**So:** wait for a successful `exec` before uploading anything, which is what
`scripts/lifecycle-check.sh` does, or upload to a path on the overlay such as `/root` rather than
one the container mounts over.

## A failing guest command is still HTTP 200

Check `exitCode` in the body. `scripts/lifecycle-check.sh` deliberately runs `sh -c 'exit 3'` and
asserts `exitCode == 3`, so the assertion that catches this is itself tested.

## Killing the server orphans running machines

On shutdown it prints `Shutting down server (VMs continue running)...`, and that is the only
notice you get, in a line you will miss if stderr is redirected. **Delete machines before killing
the server**, or they survive it with nothing managing them. `scripts/cleanup.sh` does them in
that order.

## `serve start` also reclaims stale VM directories

On startup it printed `Reclaimed 2 dangling VM data dir(es)`, which is what clears the small
leftover directories a crashed or force-killed run leaves in the cache. Worth knowing before
reporting those as a leak.

## The default listen address is derived, not hard-coded

It is a Unix socket under `XDG_RUNTIME_DIR` (`unix:///run/user/<uid>/smolvm.sock`), not a fixed
uid, despite how the help text reads when your uid happens to be 501.

## `serve openapi` writes to stdout by default

Pass `-o`, or you will paste a 150 KB spec into your terminal. On Windows it writes its
confirmation to stderr, which PowerShell renders as an error record even though the file is
written and the exit code is 0.

## There is no authentication of any kind

`serve start` exposes create, exec and file routes with no TLS, token or auth flag. On loopback
that is a single-user boundary; the Unix socket, whose file permissions are the boundary, is the
safer default and is why it is smolvm's default and this packet's.

## Field names, versions and error bodies

Those have their own page: `references/api-fields.md`. The short version is that unknown fields
are accepted with 200 and ignored, `network` and `memoryMb` are not `net` and `memory`, and the
version in the exported spec is not the binary's.
