# Credential substitution traps

Each entry was measured on v1.18.2 on 2026-09-24 on macOS arm64 and Linux aarch64, with a random
throwaway value, unless it says otherwise.

## Contents

- An environment value behaved as the one `machine start` saw
- A check that interpolates the value plants it
- A 403 or 502 with a `smolvm credentials:` body is smolvm, not the API
- The create-time rules
- Port 80 and other ports are not intercepted
- Which network backend carries it
- What the guest has, and what it does not
- `--credential` on a machine created from a pack is dropped on v1.18.2

## An environment value behaved as the one `machine start` saw

The interceptor runs in the host process that `machine start` launched, and resolves a value from
the host environment out of that process. So:

- A machine started with the variable set kept substituting after the variable was unset for a
  `machine exec`: the request went out with the start-time value and the API answered `200`
  (macOS only; not repeated on Linux, since it sends the value).
- The same machine stopped and started with the variable unset answered every substituted request
  with `smolvm credentials: credential unavailable` and a `502`, and forwarded nothing.

`docs/credential-substitution.md` says an environment value is read at `machine start` and
`machine exec` time; what was observed is start time. Rotate a value from the environment by restarting the machine, and use a
file reference for a value that has to rotate under a running machine.

## A check that interpolates the value plants it

`machine exec` commands are written to the machine's console log on the host, `agent-console.log`
in its data directory. A containment check that ran
`smolvm machine exec -- sh -c "grep -r \"$VALUE\" /proc/*/environ ..."` put the value into that log
and then found it in the machine's record. Pass it on standard input, as
`scripts/verify-containment.sh` does
(`printf '%s\n' "$VALUE" | smolvm machine exec -i ... grep -F -f /dev/stdin ...`), and never paste
a real key into an `exec` command for any reason.

## A 403 or 502 with a `smolvm credentials:` body is smolvm, not the API

Measured refusals, each decided on the host before anything was forwarded:

| request from the guest | answer |
|---|---|
| placeholder in the query string | `403 smolvm credentials: placeholders are substituted in request headers only` |
| placeholder in a form body | the same |
| the placeholder in two headers | `403 smolvm credentials: a request may carry one placeholder` |
| a made-up `SMOL_PLACEHOLDER_DEMO_...` | `403 smolvm credentials: unknown placeholder` |
| placeholder in `Cookie` | `403 smolvm credentials: placeholders are not substituted in routing or framing headers` |
| any substituted request, machine started without the value | `502 smolvm credentials: credential unavailable` |

`docs/credential-substitution.md` puts a binding that does not allow the host or the method under
a `405`. The host case is a `403`, `smolvm credentials: this credential is not allowed for this
host`, measured on v1.22.2 on macOS arm64 with two bindings. A method the binding does not allow
is a `405`, not measured here. A request to the bound host with no placeholder was forwarded and
answered normally.

## The create-time rules

```
credential "t" host "*.example.com" must be an exact lowercase DNS name (no wildcard, scheme, port or IP)
credential "t" host "93.184.215.14" must be an exact lowercase DNS name (no wildcard, scheme, port or IP)
credential "t" host "example.com" is not reachable under the machine's network allow_hosts
```

The last is a machine with `--allow-host example.org` and a credential for `example.com`: a
credential never widens what the machine may reach.

## Port 80 and other ports are not intercepted

A plain `http://` request to the bound host went straight through and was answered `200`. A
placeholder sent that way would reach the server as the literal string. Only port 443 is
intercepted.

## Which network backend carries it

A machine with a binding came up on virtio-net, `eth0 100.96.0.2/30`, with no backend named. With
`--net-backend tsi` it came up on TSI, `dummy0 203.0.113.1/24`, and the bound host's certificate was
still issued by the machine's credential CA and a placeholder in a query still got the `403`: TSI
carries the interceptor when libkrun exports `krun_set_stream_intercept`, which both v1.18.2
release libraries do, and `scripts/preflight.sh` reads that symbol. A guest that runs a VPN on the
virtio-net link needs `--guest-subnet`, which the `throwaway-machine` packet's traps cover.

## What the guest has, and what it does not

Inside the guest: the variable holds `SMOL_PLACEHOLDER_<NAME>_<32 hex>`; `/run/smol/credentials/`
holds only `ca.pem`; `SSL_CERT_FILE` and `CURL_CA_BUNDLE` point at `/run/smolvm/ca-bundle.pem` and
`NODE_EXTRA_CA_CERTS` at `ca.pem`. The value was in no process environment and no file under `/run`,
`/etc`, `/root`, `/tmp`, `/var` or `/home`, and not in the machine's directory or smolvm's database
on the host. A checkpoint of a credentialed machine, extracted on macOS, did not contain it either; its
contents are compressed, so the stronger evidence is that the guest never held the value to begin
with.

## `--credential` on a machine created from a pack is dropped on v1.18.2

`smolvm machine create --name <n> --from app.smolmachine --credential demo=VAR@example.com`
succeeded, and after `machine start` the guest's `VAR` was empty and `/run/smol/credentials` did
not exist: no placeholder, no CA, no binding. Measured on macOS arm64. The fix landed upstream after
the release (#1400, which also makes `--credential` on a restore from a `.smolcheckpoint` an
explicit error, since a checkpoint keeps the bindings it was captured with). On v1.18.2 create the
credentialed machine from an image, which is what `scripts/create-credentialed.sh` does.

**On v1.22.2 it binds.** The same `create --from` of an image pack with `--credential`, then
`machine start`, measured on macOS arm64 on 2026-10-03: one `SMOL_PLACEHOLDER` variable in the
guest's environment and `/run/smol/credentials/ca.pem` present.
