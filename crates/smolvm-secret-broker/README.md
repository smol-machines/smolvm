# Credential broker

**Scope: administrator-managed Linux deployment, not a completed cloud integration.**
The default requires process-bound Unix transport; bearer-only TCP is an explicit
compatibility/testing option, not machine identity. This standalone host process lets
an ordinary HTTP client use a placeholder environment variable while the
upstream credential stays outside the workload. Existing `--secret-env` and
`--secret-file` semantics are unchanged: those still expose values to the guest.

## Run the acceptance test

```sh
cargo build -p smolvm-secret-broker
cargo test -p smolvm-secret-broker
python3 crates/smolvm-secret-broker/tests/acceptance.py \
  --broker target/debug/smolvm-secret-broker

# Add a real Linux VM (KVM and a working Smol runtime required):
python3 crates/smolvm-secret-broker/tests/acceptance.py \
  --broker target/debug/smolvm-secret-broker --smolvm /path/to/smolvm

# TSI networking, with the credential connection over a mounted vsock socket:
python3 crates/smolvm-secret-broker/tests/acceptance.py \
  --broker target/debug/smolvm-secret-broker --smolvm /path/to/smolvm \
  --backend tsi

# Also exercise real dotenvx decryption of a temporary encrypted .env:
python3 crates/smolvm-secret-broker/tests/acceptance.py \
  --broker target/debug/smolvm-secret-broker --smolvm /path/to/smolvm \
  --backend tsi --dotenvx /path/to/dotenvx
```

The test creates its own CA, TLS service, private credential files and optional
512 MiB Alpine VM. Only installing Alpine/curl needs internet. It uses synthetic
random credentials, checks command exit codes, and deletes its VM and fixtures
on completion. It leaves unrelated machines and system trust stores untouched.
Do not interrupt it with SIGKILL; that can prevent cleanup.

## Interface

The broker accepts one **trusted host-admin configuration**, never configuration
submitted by a guest or untrusted fleet API:

```json
{
  "allow_bearer_only": true,
  "listen": "127.0.0.1:8443",
  "certificate": "/private/broker/server-chain.pem",
  "private_key": "/private/broker/server.key",
  "access_token_file": "/private/broker/workload-access",
  "grants": [{
    "host": "api.example.com",
    "port": 443,
    "placeholder": "SMOL_PLACEHOLDER_EXAMPLE_KEY",
    "header": "authorization",
    "methods": ["GET", "HEAD"],
    "secret_file": "/private/broker/upstream-key"
  }]
}
```

The example above is the compatibility test interface. For deployed workloads,
use the [process-bound service configuration](deploy/README.md) instead.

Supply a server certificate covering the configured destinations, signed by a
dedicated development CA. Only the CA's **public certificate** enters the guest;
neither its private key nor the broker's private key does. Private reference files
must be absolute, regular, owner-private files, containing 16–8192 bytes. Their
directories must not be guest-writable. The host administrator is trusted.

For local testing, Smol's existing internal `SMOLVM_GUEST_HOST_SERVICE` bridge
maps exactly one guest gateway port to this loopback listener. The acceptance
test sets `SMOLVM_EGRESS_FLOOR=strict` and uses virtio-net; it does not grant
general host-loopback access. This internal bridge is not yet a public broker
attachment API and must not overwrite an existing rollout-service mapping.

### TSI transport

TSI does not have the virtio-net gateway-port mapping. On Unix hosts, configure
`"unix_socket": "/private/broker/broker.sock"` alongside the loopback listener.
The parent directory must already be 0700; the socket is created as 0600. The
broker refuses to overwrite an existing path and removes only its own socket on
graceful shutdown. Both listeners share the same 32-session limit.

Use the existing `machine create --mount-socket` option to attach **only that
socket**, not the host credential directory:

```sh
smolvm machine create --name worker --image alpine:3.20 --net --net-backend tsi \
  --mount-socket /private/broker/broker.sock:/run/smol-broker.sock
smolvm machine start --name worker
smolvm machine exec --name worker -- apk add --no-cache curl socat
smolvm machine exec --name worker --detach -- \
  socat TCP4-LISTEN:7443,bind=127.0.0.1,reuseaddr,fork UNIX-CONNECT:/run/smol-broker.sock
```

The workload's standard HTTPS proxy is then `http://smol:ACCESS_TOKEN@127.0.0.1:7443`.
This listener is guest-local; vsock carries its bytes to the private host socket.
The application needs no socket-specific client API. Provision the public CA and
placeholder environment as above. The broker and VMM must have permission to
access the private socket; the test uses a same-user local CLI, not isolated fleet
UIDs. No permissions are widened automatically.

This does **not** repair TSI's general egress filtering or make it equivalent to
strict virtio-net networking. Do not apply virtio-net gateway addresses or claim
its strict egress floor for TSI. Host-enforced fleet egress remains a separate gate.

The client uses standard `https_proxy`/`HTTPS_PROXY`, a public CA bundle, and the
placeholder in its normal credential variable. Proxy Basic username is `smol`;
the password is a separately revocable capability from `access_token_file`.
Example guest request (after the administrator configures the connection):

```sh
curl -H "Authorization: Bearer $EXAMPLE_API_KEY" https://api.example.com/user
```

No service-specific SDK or agent launcher is required. An external secrets
manager may render credentials to the protected file.

## Dotenvx integration

The implemented integration uses dotenvx's existing **host-side process
environment injection**, not its unreleased Agentic Secrets Gateway API.
Replace a grant's `secret_file` with `secret_env` (exactly one is required):

```json
{
  "host": "api.example.com",
  "placeholder": "SMOL_PLACEHOLDER_EXAMPLE_KEY",
  "header": "authorization",
  "secret_env": "EXAMPLE_API_KEY"
}
```

Then launch **only the broker** under dotenvx:

```sh
dotenvx run --strict -f /private/broker/.env -- \
  smolvm-secret-broker /private/broker/config.json
```

Dotenvx decrypts into the broker's environment. Start Smol separately, outside
that wrapped process, and give the guest the placeholder, proxy capability, and
public CA only. Never mount `.env.keys`, the credential files, or the broker's
private certificate key into the VM. Do not wrap the guest application or Smol
launcher in the credential-bearing `dotenvx run` process.

Environment credentials are a startup snapshot: changing the encrypted `.env`
requires restarting the broker. Removing/rotating the private access-token file
still revokes subsequent requests immediately, including on existing connections.
File-backed credential sources retain live rotation. Dotenvx is optional; any
trusted host-side manager can populate the same environment/file seam.

## Enforced behavior

- Grants default to GET and HEAD. Administrators must explicitly allow POST,
  PUT, PATCH, DELETE or OPTIONS where needed; method restrictions do not replace
  narrowly scoped upstream credentials.
- Authenticated CONNECT to exact configured DNS host and port only. No raw
  tunnels; TLS is terminated locally and upstream TLS is independently verified.
- Request Host must match CONNECT; absolute-form targets and upgrades are
  rejected. Upstream redirects are returned, never followed by the broker.
- Only exact configured placeholders in `Authorization` (raw or Bearer) or
  `X-API-Key` are substituted. No body/query, Basic-auth, signing, or arbitrary
  header substitution. Other detected placeholder locations are rejected.
- Authorization is reread on every HTTP request, including keep-alive requests;
  it is checked again after receiving the body, before upstream dispatch.
  Rotation/removal rejects subsequent uses of an old capability. An already
  dispatched upstream operation cannot be revoked or undone.
- Upstream credentials are read per request (environment values do not refresh
  from `.env` files without restarting). Missing/unreadable credentials fail
  closed with a generic error; no plaintext fallback and no request-value logs.
- Maximum 32 active sessions, 30 seconds per session, 1 MiB request bodies and
  4 MiB response bodies. HTTP/1.1 only; no streaming/WebSockets or encoded bodies.
  Overloaded connections are closed rather than queued outside the deadline.
- Hop-by-hop/proxy credentials are stripped. Plaintext credential reflection in
  upstream response headers/body is refused. This is defense in depth, not DLP:
  a trusted upstream can encode or transform a credential and return it.

## Explicit remaining boundaries

See [the Linux service template](deploy/README.md) for a separately owned broker
and its tested limits. The template is not installed automatically. Same-user
dotenvx testing and isolated-service testing are separate acceptance cases;
neither establishes a complete desktop-to-cloud deployment.

The combined Linux isolated-service + dotenvx + real-VM test now covers branch
and restart authorization, including a live TLS session at the branch boundary.
Portable capture currently refuses published sockets in SmolVM; do not remove
that guard or claim checkpoint/restore support for this attachment. A restored
machine must be attached and authorized by its administrator as a new process.

- The proxy token is guest-visible and copyable. In process-bound mode it is
  necessary but not sufficient: the host-admin record must also authorize the
  kernel-observed peer. Compatibility bearer-only mode does not have that property.
- The test keeps public egress for Alpine/curl setup. It verifies the protected
  broker path and blocked unrelated host access, not universal forced proxying.
  A guest can bypass proxy environment variables, but gets no upstream key by
  doing so. Production gateway-only routing needs host-enforced policy.
- A host-level agent with root/sudo can read broker files or memory. Service
  separation protects against ordinary users, not the host administrator.
- Method restrictions do not constrain every API action. Use narrow upstream keys;
  provider-specific resource/body policy is not implemented.
- Public fleet APIs, dotenvx gateway-specific integration, CLI/SDK automatic attachment and trust provisioning,
  portable attachment restore, cross-platform process-bound QA and independent
  security review remain outside this Linux-only slice.
