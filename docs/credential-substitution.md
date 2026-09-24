# Credential substitution

Give a workload a credential it can use but never read. The guest receives an
opaque placeholder in the environment variable it expects; the host replaces
the placeholder with the real value only on HTTPS requests to the hosts you
allow, and only inside a request header. The value never enters the machine,
its record, or a checkpoint.

```sh
NOTION_API_KEY=secret_… smolvm machine create --name notes --image alpine:3.20 \
  --credential notion=NOTION_API_KEY@api.notion.com
smolvm machine start --name notes

smolvm machine exec --name notes -- sh -c \
  'echo "$NOTION_API_KEY"; curl -sS -H "Authorization: Bearer $NOTION_API_KEY" \
   -H "Notion-Version: 2022-06-28" https://api.notion.com/v1/users/me'
# SMOL_PLACEHOLDER_NOTION_7F3A…      <- all the guest ever holds
# {"object":"user", …}                <- Notion received the real key
```

The same placeholder sent anywhere else — another host, a query string, a
request body — is refused or travels as the literal placeholder string.

## Declaring bindings

A binding names a credential, the guest variable that receives its
placeholder, and the exact hosts it may be sent to. It never carries the value.

Command line (repeatable, implies `--net`):

```sh
--credential NAME=ENV_VAR@HOST[,HOST...]
```

Smolfile:

```toml
[network]
allow_hosts = ["api.notion.com", "api.github.com"]   # optional

[[network.credentials]]
name = "notion"
environment_variable = "NOTION_API_KEY"
allowed_hosts = ["api.notion.com"]

[[network.credentials]]
name = "github"
environment_variable = "GITHUB_TOKEN"
allowed_hosts = ["api.github.com"]
methods = ["GET", "HEAD"]        # optional; default is every method
```

API (`POST /v1/machines`): the same object under `credentials`, with
`injection_location: { "header": true }` accepted for compatibility.

Rules checked at create:

- `allowed_hosts` are exact lowercase DNS names — no wildcards, IPs, schemes or
  ports — and the list must be non-empty. A credential is never sent anywhere
  by default.
- When the machine also has `allow_hosts`, every credential host must fall
  under it. Widening the machine's network never widens a credential, and a
  credential never grants reachability the network does not.
- Binding names and environment variables are unique within a machine.

## Where the value comes from

The host resolves each binding on every request, so rotating a credential
needs no restart, and nothing is cached across requests.

1. A `[secrets]` reference (or `--secret-env` / `--secret-file`) under the
   **same variable name** as the binding's `environment_variable`. That
   reference feeds the substitution instead of being injected as plaintext.
2. Otherwise, the host environment variable of that name at `machine start`
   and `machine exec` time. This is the `dotenvx run -- smolvm machine start …`
   path: decrypted values live only in the host process.

```toml
[secrets]
NOTION_API_KEY = { from_file = "/run/secrets/notion" }   # rotated in place, read per request
```

Embedders resolve however they like: the engine asks a `CredentialResolver`
with the machine name, binding name, destination host and port, method and
path, and expects the raw value back. See `crates/smolvm-credentials`.

## What the guest sees

- `ENV_VAR=SMOL_PLACEHOLDER_<NAME>_<random>` in the workload environment,
  for `start`, `exec`, `run` and `shell`. Placeholders are minted once at
  create and stay stable for the machine's lifetime.
- `/run/smol/credentials/ca.pem`: the machine's public CA, mounted read-only.
  It is name-constrained to the policy's `allowed_hosts`, so clients reject
  any certificate it signs for another domain.
  Nothing else in that directory.
- `/run/smolvm/ca-bundle.pem`: the image's own trust roots followed by the
  machine CA, assembled by the guest agent at boot so clients keep trusting
  public hosts.
- `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `GIT_SSL_CAINFO`
  pointing at the bundle; `NODE_EXTRA_CA_CERTS` and `DENO_CERT` at `ca.pem`.
  curl, Python, Node, Deno, Git and anything using OpenSSL defaults work
  unmodified. A client with its own trust store (Java keystores, some Go
  binaries with pinned roots) needs `ca.pem` added to it.

## What happens to a request

HTTPS connections from the guest are redirected to an interceptor running in
the machine's host process, after the machine's egress policy has admitted
the destination. The interceptor reads the TLS server name:

- **A host some binding allows**: TLS is terminated with a certificate issued
  by the machine CA, the request is parsed as HTTP/1.1, and the placeholder is
  replaced in place — the guest supplies `Bearer `, `Basic `, or any other
  surrounding syntax, and only the placeholder changes. The request is then
  sent to the destination address the guest resolved, over a fresh TLS
  connection verified for that host. Responses stream back, including
  server-sent events.
- **Any other host**: the bytes are relayed untouched. The guest sees the real
  server's certificate, and a placeholder in such a request is just a string.

Refused with a `403` and a one-line reason in the body:

- a placeholder in the path, query string or request body;
- a placeholder in a routing or framing header (`Host`, `Content-Length`,
  `Transfer-Encoding`, `Connection`, `Cookie`, …);
- more than one placeholder in a request;
- a placeholder the machine did not mint, or one whose binding does not allow
  this host or method (`405`).

`502 smolvm credentials: credential unavailable` means the host could not
resolve the binding — the variable is unset, the file is missing or
unreadable, or the value has control characters. Details are in the machine's
host log, never in the response.

A request to an allowed host that carries no placeholder is forwarded as is.

## Branching and checkpoints

`machine branch` children inherit the golden's placeholders and trust the same
CA, so processes restored from the snapshot keep working without restarting.
Each child resolves under its own machine name: a resolver can hand different
values to different branches, or refuse one branch, without touching the rest.

Placeholders and the policy travel with portable checkpoints. Restoring on a
different host regenerates the CA, so already-running processes captured in
the checkpoint distrust the interceptor until they restart; new processes are
fine.

## Backends and limits

- A credential policy selects the `virtio-net` backend by default (like
  `--allow-host` does). `--net-backend tsi` works only with a libkrun that
  provides `krun_set_stream_intercept`; otherwise start fails with a message
  saying so.
- Interception covers port 443. Plaintext HTTP on port 80 and other ports are
  relayed without substitution.
- The guest side is HTTP/1.1 (the interceptor negotiates `http/1.1` only);
  upstream may be HTTP/2. WebSocket upgrades and `CONNECT` are refused on
  credential hosts.
- Request bodies are buffered up to 8 MiB on credential hosts; responses are
  not buffered.
- An upstream can still return a credential in its response body. This is
  substitution, not data-loss prevention.

## Comparison with `--secret-env` / `--secret-file`

Those inject the plaintext into the guest environment: convenient, but a
compromised workload can read and exfiltrate it. A credential binding gives
the workload the *ability to use* the value at named hosts and nothing else.
Use secrets injection for values a program must read (a database URL it
parses); use credential bindings for bearer tokens and API keys that only ever
appear in a request header.

## External host interceptor

A local orchestrator can own interception instead of using the built-in
credential resolver:

```sh
smolvm machine create --name worker --net --image alpine:3.20
SMOLVM_INTERCEPTOR_TOKEN="$TOKEN" smolvm machine start --name worker \
  --egress-interceptor 127.0.0.1:43123
```

The address must be loopback; IPv6 uses `[::1]:43123`. `TOKEN` is the same
random 32-byte token held by the interceptor, encoded as 64 hexadecimal
digits. It is read from the host environment, never forwarded to the guest
or saved in the machine definition. Supply the address and token again after
stopping the machine. A running machine must be stopped before changing the
endpoint.

This selects `virtio-net` and redirects every admitted outbound TCP connection,
including non-HTTPS ports and IPv6, to the service. The machine's egress
allowlist still applies before interception. Gateway DNS remains host-managed;
other outbound UDP and ICMP are blocked. An unavailable interceptor, rejected
connection, or failed handshake never falls back to dialing the destination.
TSI, named/pod networks, checkpoint/branch launches, and simultaneous built-in
credential bindings are rejected.

The service implements the existing handshake in
[`smolvm-protocol::intercept`](../crates/smolvm-protocol/src/intercept.rs):
validate the per-launch token and original destination, send a one-byte
connection verdict, then handle the stream. Use a different token for each
machine launch to associate connections with its policy. The service owns
TLS handling and credential resolution; the caller installs its CA and
placeholder environment variables in the guest. No `HTTPS_PROXY` setting is
needed.
