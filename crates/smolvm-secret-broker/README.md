# Credential broker: first functional slice

**Experimental. Synthetic/local testing only; not a production security boundary
or a completed dotenvx/cloud integration.** This standalone host process lets
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
  "listen": "127.0.0.1:8443",
  "certificate": "/private/broker/server-chain.pem",
  "private_key": "/private/broker/server.key",
  "access_token_file": "/private/broker/workload-access",
  "grants": [{
    "host": "api.example.com",
    "port": 443,
    "placeholder": "SMOL_PLACEHOLDER_EXAMPLE_KEY",
    "header": "authorization",
    "secret_file": "/private/broker/upstream-key"
  }]
}
```

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

The client uses standard `https_proxy`/`HTTPS_PROXY`, a public CA bundle, and the
placeholder in its normal credential variable. Proxy Basic username is `smol`;
the password is a separately revocable capability from `access_token_file`.
Example guest request (after the administrator configures the connection):

```sh
curl -H "Authorization: Bearer $EXAMPLE_API_KEY" https://api.example.com/user
```

No service-specific SDK or agent launcher is required. An external secrets
manager may render credentials to the protected file. This does not claim a
dotenvx gateway API exists or has been integrated.

## Enforced behavior

- Authenticated CONNECT to exact configured DNS host and port only. No raw
  tunnels; TLS is terminated locally and upstream TLS is independently verified.
- Request Host must match CONNECT; absolute-form targets and upgrades are
  rejected. Upstream redirects are returned, never followed by the broker.
- Only exact configured placeholders in `Authorization` (raw or Bearer) or
  `X-API-Key` are substituted. No body/query, Basic-auth, signing, or arbitrary
  header substitution. Other detected placeholder locations are rejected.
- Authorization is reread on every HTTP request, including keep-alive requests;
  rotation/removal rejects subsequent uses of an old capability. An already
  dispatched upstream operation cannot be revoked or undone.
- Upstream credentials are read per request. Missing/unreadable credentials fail
  closed with a generic error; no plaintext fallback and no request-value logs.
- Maximum 32 active sessions, 30 seconds per session, 1 MiB request bodies and
  4 MiB response bodies. HTTP/1.1 only; no streaming/WebSockets or encoded bodies.
- Hop-by-hop/proxy credentials are stripped. Plaintext credential reflection in
  upstream response headers/body is refused. This is defense in depth, not DLP:
  a trusted upstream can encode or transform a credential and return it.

## Explicit remaining boundaries

- This initial proxy capability is guest-visible and copyable. It is **not**
  host-attested machine identity. Branches/checkpoints copying it share the same
  authorization until revoked. Independent child identity, restore reauthorization,
  and per-machine gateway attachment still need lifecycle integration.
- The test keeps public egress for Alpine/curl setup. It verifies the protected
  broker path and blocked unrelated host access, not universal forced proxying.
  A guest can bypass proxy environment variables, but gets no upstream key by
  doing so. Production gateway-only routing needs host-enforced policy.
- A host-level agent with the administrator's permissions can read broker files
  or memory. This prototype does not provide privilege separation from that actor.
- Host authorization does not constrain API actions. Use narrow upstream keys;
  resource/method/body policy belongs in the broker/provider integration.
- Public fleet APIs, dotenvx, CLI/SDK automatic attachment and trust provisioning,
  branch/restore acceptance, OS privilege separation, cross-platform QA, and
  independent security review remain before a production claim.
