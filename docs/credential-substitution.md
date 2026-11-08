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

The same placeholder sent anywhere else — another host, a query string, or a
request body without an explicit form-body binding — is refused or travels as
the literal placeholder string.

A binding can instead set a header outright, so the guest needs no
placeholder at all (see [Setting a header](#setting-a-header)).

## Declaring bindings

A binding names a credential, the guest variable that receives its
placeholder, and the exact hosts it may be sent to. It never carries the value.

Command line (repeatable, implies `--net`):

```sh
--credential NAME=ENV_VAR@HOST[,HOST...][:body][:set-header=HEADER]
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

For an OAuth refresh token sent in a form body, add `:body` to the CLI
binding or set `injection_location = { header = true, body = true }` in a
Smolfile. The host substitutes placeholders only in
`application/x-www-form-urlencoded` request bodies to the binding's hosts and
methods. The default remains header substitution only. For example:

```sh
smolvm machine create --name oauth --image curlimages/curl:8.11.1 \
  --allow-host auth.example.com \
  --secret-file REFRESH_TOKEN=/path/to/refresh-token \
  --credential refresh=REFRESH_TOKEN@auth.example.com:body
```

Inside the VM, `curl -d "grant_type=refresh_token&refresh_token=$REFRESH_TOKEN"
https://auth.example.com/token` sends the host's current file value as one
percent-encoded form field. The same placeholder in a header and the form body
of one request is allowed; two different placeholders are refused.

The CLI accepts `:body` and `:set-header=HEADER` together in either order:
`:body:set-header=HEADER` or `:set-header=HEADER:body`.

API (`POST /api/v1/machines`): the same object under `credentials`, with
`injection_location: { "header": true, "body": true }` for form-body
substitution (omit `body` to keep the default).

Rules checked at create, and whenever bindings are replaced:

- `allowed_hosts` are lowercase DNS names, or a whole-label wildcard
  `*.example.com` that matches every subdomain of `example.com` but not
  `example.com` itself (list both to cover both). No IPs, schemes, ports or
  `*.com`-style public-suffix wildcards, and the list must be non-empty. A
  credential is never sent anywhere by default.
- When the machine also has `allow_hosts`, every credential host must fall
  under it. Widening the machine's network never widens a credential, and a
  credential never grants reachability the network does not.
- Binding names and environment variables are unique within a machine.

## Changing bindings after create

A machine's bindings can be replaced in any state: created, stopped, paused or
running. The new set is exactly what you send, validated as create validates
it, and stored on the machine, so every later start, resume, restore and branch
uses it.

```sh
# HTTP API: the complete set, each binding as in the create body
curl -X PUT http://127.0.0.1:8080/api/v1/machines/notes/credentials \
  -H 'Content-Type: application/json' --data-binary @- <<'JSON'
{"credentials":[
  {"name":"notion","environment_variable":"NOTION_API_KEY","allowed_hosts":["api.notion.com"]},
  {"name":"github","environment_variable":"GITHUB_TOKEN","allowed_hosts":["api.github.com"]}
]}
JSON
# then the values, for a machine whose values are supplied:
curl -X PUT http://127.0.0.1:8080/api/v1/machines/notes/credential-values \
  -H 'Content-Type: application/json' -d '{"values":{"notion":"…","github":"…"}}'

# CLI: add or replace a binding by name, or remove one
smolvm machine update --name notes --credential github=GITHUB_TOKEN@api.github.com
smolvm machine update --name notes --remove-credential notion
```

The embedded runtime has `set_credential_bindings(name, policy)`. An empty list
leaves the machine with no binding. The route answers with the machine's info,
`400` for bindings create would refuse, and `409`, with nothing changed, when the
machine cannot take them now (below).

On a running machine the change applies from its next request, with no restart:

- A binding kept by name keeps its placeholder, so processes already holding it
  keep working, even if its hosts or methods changed.
- A new binding gets a new placeholder. Commands started from then on (`exec`,
  `shell`, the API's exec) see it in their environment; processes already
  running keep the environment they started with. Its value comes from
  `credential-values` (API and embedded machines) or, for a CLI machine, from
  the variable it names in the environment of `machine update`.
- A removed binding stops being substituted at once. A new connection to its
  host is relayed untouched, so its placeholder goes out as a plain string; a
  request on a connection the interceptor already terminated is refused as an
  unknown placeholder. The value held for it is dropped.
- A host outside the machine's CA widens the CA: it is re-certified with the
  same key, so processes that loaded the earlier certificate keep trusting the
  hosts it covered, and the guest agent installs the wider one in the machine
  root and every workload container for commands started from then on. The CA
  never narrows.

A machine that booted without bindings gains them live when it runs on
virtio-net with outbound access (every networked machine under `serve`, and
any networked machine with an allow list or published ports): the first
bindings start the interceptor in its host process, and the guest agent
installs the CA. A running machine is refused, with nothing changed, when:

- it has no network device: libkrun fixes a VM's devices when it starts;
- it runs on TSI: libkrun redirects connections to an interceptor only through
  a hook it takes before the VM starts;
- it has inbound-only networking (published ports, no egress): its network
  runtime started deny-all and cannot open egress while it runs;
- its guest agent predates live trust and the change needs the CA installed
  (first bindings, or a host outside the CA).

Stop it, set the bindings, and start it again. A paused or restored machine
resumes the devices its memory was saved with, so a first binding that needs
another network backend (from none or TSI to virtio-net) is refused; one on
virtio-net takes it, and its guest gets the CA through its agent on resume.

Removing every binding keeps the machine's CA, interceptor and network backend,
so a checkpoint taken while it had bindings still restores, and bindings added
later apply live.

Bindings replaced over the API or by an embedder take their values only from
what is supplied, as at create; so do the bindings a machine already had from
such a caller, even when the CLI edits them later.

## Setting a header

A binding with `set_header` sets that request header to the credential's
value on every request to its hosts with its methods, replacing whatever the
guest sent. The value is the whole header value, `Bearer …` or `Basic …`
included. With the CLI form, `ENV_VAR` still receives an unused opaque
placeholder in the guest; the complete secret value and resolved header remain
on the host. This is the shape of a firewall that brokers credentials by
domain, for clients you cannot point at a placeholder (a `git clone` of a
private repository, say).

On the CLI, add `:set-header=HEADER` to the binding. For example, this reads
the complete `GITHUB_AUTH` value from the host environment when the machine
starts and injects it as the `Authorization` header for requests to
`api.github.com`; the guest never receives that secret:

```sh
smolvm machine create --name github --image alpine:3.20 \
  --credential github=GITHUB_AUTH@api.github.com:set-header=authorization
GITHUB_AUTH='Bearer ghp_…' smolvm machine start --name github
```

```toml
[[network.credentials]]
name = "github"
environment_variable = "GITHUB_BASIC_AUTH"   # host variable holding "Basic …"
allowed_hosts = ["github.com", "*.github.com"]
set_header = "authorization"
methods = ["GET", "POST"]
```

- `set_header` is a lowercase header name. Routing, framing and cookie
  headers (`host`, `content-length`, `transfer-encoding`, `connection`,
  `cookie`, …) are refused.
- A request whose method the binding does not allow is forwarded without the
  header, as the guest sent it.
- Two bindings may not set the same header for hosts that overlap.
- If the value cannot be resolved the request fails with a `502` rather than
  going out without it.
- `environment_variable` still names where the CLI reads the value from, and
  still receives a (then unused) placeholder in the guest. A binding whose
  values are supplied by an API caller or embedder may omit it.

## Where the value comes from

The host resolves each binding on every request, in the process `machine start`
launched. A file reference is therefore read fresh each time, so rotating the
file needs no restart. An environment variable is read from the environment
`machine start` ran with, so changing it later, including on a `machine exec`,
has no effect until a restart.

1. A `[secrets]` reference (or `--secret-env` / `--secret-file`) under the
   **same variable name** as the binding's `environment_variable`. That
   reference feeds the substitution instead of being injected as plaintext.
2. Otherwise, the host environment variable of that name, as `machine start`
   saw it. This is the `dotenvx run -- smolvm machine start …` path: decrypted
   values live only in the host process.

```toml
[secrets]
NOTION_API_KEY = { from_file = "/run/secrets/notion" }   # rotated in place, read per request
```

Machines created over the HTTP API take their values only from
`PUT /api/v1/machines/{name}/credential-values`. Machines created through the
embedded runtime (`create_machine_with_credentials`) take them only from
`supply_credential_values`. Neither ever falls back to this host's
environment. Supplied values are held in the supplying process's memory,
never written anywhere, and apply from the machine's next start; a running
machine also gets them at once, so its next request to a bound host carries the
new value without a restart. A value naming no binding of the machine is
refused, and a running machine that cannot take values live (one started before
live values were supported) fails the call while keeping them for its next start.

Embedders resolve however they like: the engine asks a `CredentialResolver`
with the machine name, binding name, destination host and port, method and
path, and expects the raw value back. See `crates/smolvm-credentials`.

## What the guest sees

- `ENV_VAR=SMOL_PLACEHOLDER_<NAME>_<random>` in the workload environment,
  for `start`, `exec`, `run` and `shell`. A binding's placeholder is minted when
  the binding is added and stays the same while the machine has it.
- `/run/smol/credentials/ca.pem`: the machine's public CA, mounted read-only,
  or written by the guest agent when the machine gained its bindings after
  boot. It is name-constrained to the hosts its bindings have named, so
  clients reject any certificate it signs for another domain.
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

- a placeholder in the path or query string, or in a request body when the
  binding lacks `:body`;
- a placeholder in a routing or framing header (`Host`, `Content-Length`,
  `Transfer-Encoding`, `Connection`, `Cookie`, …);
- more than one placeholder in a request;
- a placeholder the machine did not mint, or one whose binding does not allow
  this host or method (`405`).

Under `:body`, a request body that is not `application/x-www-form-urlencoded`
is refused with a `415`.

`502 smolvm credentials: credential unavailable` means the host could not
resolve the binding — the variable is unset, the file is missing or
unreadable, or the value has control characters. Details are in the machine's
host log, never in the response.

A request to an allowed host that carries no placeholder is forwarded as is.

## Branching and checkpoints

`machine branch` children inherit the golden's bindings and placeholders and
trust the same CA, so processes restored from the snapshot keep working without
restarting. A child's bindings can then be replaced like any machine's; a new
host widens the lineage's shared CA, which never narrows, so its siblings keep
trusting theirs.
Each child resolves under its own machine name: a resolver can hand different
values to different branches, or refuse one branch, without touching the rest.
Values supplied for the golden (over the API or the embedded runtime) are used
by its branches too, until values are supplied for a branch itself.

Placeholders, the policy and the CA travel with portable checkpoints, so
processes captured in a checkpoint keep trusting the interceptor after a
restore. Values never travel: supply them again for the restored machine. A
restored machine starts with the bindings it was captured with; replace them
after the restore, before or after its first start.

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
parses); use credential bindings for bearer tokens and API keys sent in headers
or form bodies to explicit hosts.

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
or saved in the machine definition. After the first intercepted start, the
machine record remembers that interception is required. Supply the address
and token on every later start; starts without them fail closed. A running
machine must be stopped before changing the endpoint.

Stop any monitor process first. To intentionally return a stopped machine to
normal network egress, run
`smolvm machine update --name worker --no-egress-interceptor`. The next start
then uses the machine's regular network policy.

For automatic restarts, pass the same options to the monitor process:

```sh
SMOLVM_INTERCEPTOR_TOKEN="$TOKEN" smolvm machine monitor --name worker \
  --restart always --egress-interceptor 127.0.0.1:43123
```

The API can also bind the interceptor in the start request body:

```sh
curl -X POST http://127.0.0.1:8080/api/v1/machines/worker/start \
  -H 'Content-Type: application/json' --data-binary @- <<EOF
{"egressInterceptor":{"address":"127.0.0.1:43123","token":"$TOKEN"}}
EOF
```

The API server keeps the binding in memory for automatic and implicit restarts,
but never writes the token to the machine record or returns it in responses.
After the API server itself restarts, supply the binding again on the next
stopped-machine start. A running machine must be stopped before rebinding.
Every start path fails closed if the binding is unavailable. Keep the
interceptor service available before starting or restarting the machine.

This selects `virtio-net` and redirects every admitted outbound TCP connection,
including non-HTTPS ports and IPv6, to the service. The machine's egress
allowlist still applies before interception. Gateway DNS remains host-managed;
other outbound UDP and ICMP are blocked. An unavailable interceptor, rejected
connection, or failed handshake never falls back to dialing the destination.
TSI, named/pod networks, and simultaneous built-in credential bindings are
rejected. The versioned mediated mode supports API branches and checkpoint
restore with a fresh binding; see [mediated egress](mediated-egress.md).

The service implements the existing handshake in
[`smolvm-protocol::intercept`](../crates/smolvm-protocol/src/intercept.rs):
validate the per-launch token and original destination, send a one-byte
connection verdict, then handle the stream. Use a different token for each
machine launch to associate connections with its policy. The service owns
TLS handling and credential resolution; the caller installs its CA and
placeholder environment variables in the guest. No `HTTPS_PROXY` setting is
needed.
