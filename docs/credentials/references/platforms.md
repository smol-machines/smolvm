# Per-platform arms

| | macOS arm64 | Linux aarch64 | Linux x86_64 | Windows x86_64 |
|---|---|---|---|---|
| run here | every script, v1.22.2 and v1.18.2 | every script, v1.18.2 | not run | not run |
| default backend with a binding | virtio-net | virtio-net | not run | not run |
| `--net-backend tsi` with a binding | intercepted | intercepted | not run | not run |
| `krun_set_stream_intercept` in the release libkrun | yes (`libkrun.dylib`) | yes (`libkrun.so`) | not checked | not checked |

## macOS arm64

macOS 26.6.2, v1.18.2, 2026-09-24. `preflight.sh`, `create-credentialed.sh`,
`verify-containment.sh` and `cleanup.sh` end to end, `result=contained`, plus the refusals, the
create-time rules, the `502`, the TSI backend and a checkpoint of a credentialed machine. On
v1.22.2, 2026-10-03, macOS 27.0.1: every script again, bound to a local HTTPS server,
`result=contained`, the two refusals, `tsi_stream_intercept=yes`, and `--credential` on a machine
created from a pack binding where v1.18.2 dropped it.

## Linux aarch64

Lima `linux-kvm`, Ubuntu 24.04, v1.18.2, 2026-09-24. The same checks with the same answers, word
for word. Every delete prints `WARN unable to lock UID registry; retaining assignment`, which is
harmless.

## Linux x86_64 and Windows

Not run for this packet.
