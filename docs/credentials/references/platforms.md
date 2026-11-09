# Per-platform arms

| | macOS arm64 | Linux aarch64 | Linux x86_64 | Windows x86_64 |
|---|---|---|---|---|
| run here | every script, v1.22.2 and v1.18.2 | every script, v1.18.2 | not run | by hand, v1.34.0 |
| default backend with a binding | virtio-net | virtio-net | not run | intercepted |
| `--net-backend tsi` with a binding | intercepted | intercepted | not run | intercepted |
| `krun_set_stream_intercept` in the release libkrun | yes (`libkrun.dylib`) | yes (`libkrun.so`) | not checked | yes (`krun.dll`) |

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

## Windows x86_64

Windows 11 Home build 10.0.26200 UBR 9711, v1.34.0, 2026-11-09, elevated PowerShell. The scripts
are bash, so their commands were issued by hand, with a random throwaway value in the host
variable and `example.com` as the bound host. The guest variable held a `SMOL_PLACEHOLDER_` value;
the guest saw the credential CA, `issuer=O=smolvm machine credentials, CN=smolvm smolskill-cred
credential CA`, for `example.com` and the real issuer for another host; the placeholder in a query
string was refused, `smolvm credentials: placeholders are substituted in request headers only
[403]`; and the value was in no file under `%LOCALAPPDATA%\smolvm` but the `.raw` disk images, which
were not searched. The
same with `--net-backend tsi`: placeholder, and the credential CA.

**The guest search in `verify-containment.sh` cannot run there.** It hands the value to the guest
on standard input through `machine exec -i`, and on Windows `exec -i` forwards nothing from a pipe
or a file: `cat` and `head -n1` were still waiting after 30 s, with the input redirected by
`Start-Process`, by `cmd`'s `<` and by a PowerShell pipe. The client waits only on console input
there (`src/agent/terminal.rs:479-514` at v1.34.0). Search for a part of the value that is not
secret instead: with a value that began with a fixed prefix, `grep -rlF <prefix>` over the same
guest paths found 0 files.

## Linux x86_64

Not run for this packet.
