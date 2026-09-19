# Linux service setup

This template keeps broker administration and credentials separate from an
unprivileged desktop/agent user. The admin installs root-owned binaries/config
and systemd creates an ephemeral service identity. The agent must have **no
sudo, root access, systemd administration, or permission to change these files**.
This cannot protect against a host administrator. On a development host where
the agent has unrestricted passwordless sudo, use a separately administered host.

## Administrator setup

This is a deployment template, not an automatic installer. Review the trust
model and configure narrowly scoped upstream credentials before deploying:

1. Install the broker as root-owned `/usr/local/bin/smolvm-secret-broker` and
   the provided launcher as root-owned, mode 0755
   `/usr/local/libexec/smolvm-secret-broker-start`.
2. Create root-owned `/etc/smolvm-secret-broker`, mode 0700. Supply the six files
   named by `LoadCredential`, mode 0600. No actual values appear in the unit or
   command line. The upstream CA file is an explicit additional trust root;
   omit that LoadCredential, launcher item and config field together when only
   public WebPKI trust is wanted.
3. The config must reference service-private runtime copies, for example:

```json
{
  "listen": null,
  "unix_socket": "/run/smolvm-secret-broker/broker.sock",
  "peer_identity_file": "/run/smolvm-secret-broker/identity",
  "certificate": "/run/smolvm-secret-broker/leaf",
  "private_key": "/run/smolvm-secret-broker/key",
  "access_token_file": "/run/smolvm-secret-broker/access",
  "upstream_ca": "/run/smolvm-secret-broker/ca",
  "grants": [{
    "host": "api.example.com",
    "placeholder": "SMOL_PLACEHOLDER_EXAMPLE_KEY",
    "header": "authorization",
    "methods": ["GET", "HEAD"],
    "secret_file": "/run/smolvm-secret-broker/secret"
  }]
}
```

4. Install the unit root-owned in `/etc/systemd/system`, reload systemd, and
   start it. Attach only `/run/smolvm-secret-broker/broker.sock` using the existing
   `--mount-socket` option and copy the public CA into the guest. Never mount the
   runtime directory. This works with TSI and does not expose host networking.
   The directory is traverse-only (0711), credentials remain 0600, and the socket
   accepts a connection only after checking kernel-reported PID/UID and process
   start time against the protected authorization record.
5. After starting the machine, use `machine status --json` to obtain its VMM PID.
   `smolvm-secret-broker identity VMM_PID` prints a JSON record with PID, effective
   UID, start ticks and host boot ID. A trusted administrator publishes this as
   the configured `identity` file, mode 0600, owned by the service UID (the owner
   of `/run/smolvm-secret-broker`). Use a temporary file in that directory and
   rename to publish atomically. No authorization record means no access.

One broker authorizes one process incarnation. To serve independent simultaneous
machines, use separate service/config/runtime instances and distinct access
tokens. Children share their source's host UID, so **UID alone is insufficient**.
The broker checks the full process identity at accept, per HTTP request and again
after reading the request body. A child or restarted VM requires a new explicit
grant; a token inherited from its parent does not suffice. Replacing the record
transfers access; deleting it revokes subsequent dispatches. The helper only
prints process metadata; it does not grant access or attest machine ownership.

The record belongs outside the VM and its snapshots. Portable checkpoint capture
currently rejects published sockets in SmolVM, including this attachment. The operator must attach
and authorize any new/restored process separately. No guest API can issue grants.

`LoadCredential` and the private tmpfs copies are startup snapshots. To rotate
or revoke access in this deployment, the administrator updates the root-owned
source and **restarts the service**; the old service's connections terminate.
Changing source files alone does not update the running service. Restart can
leave the outcome of an already-dispatched upstream operation unknown; do not
automatically retry non-idempotent API operations.

Dotenvx must also run under the service identity, never the agent's identity.
For encrypted-env mode, replace `secret_file` with `secret_env`, load the encrypted
env and decryption-key files with `LoadCredential`, copy them to private runtime
files, and wrap only the broker with `dotenvx run`. Supply a private runtime home
to dotenvx: DynamicUser has no normal home, and dotenvx otherwise fails before
launching. The provided launcher enables this with a root-owned systemd override:

```ini
[Service]
Environment=SMOL_BROKER_DOTENVX=/usr/local/bin/dotenvx
Environment=HOME=/run/smolvm-secret-broker/home
LoadCredential=env:/etc/smolvm-secret-broker/.env
LoadCredential=envkeys:/etc/smolvm-secret-broker/.env.keys
```

The launcher uses dotenvx 2.28.0 flags. The `secret`
credential loaded by the base template is unused when the config uses `secret_env`;
it can be an empty private file, not a second plaintext copy of the upstream key.

## Scope limits

Fleet/control-plane automation and macOS/Windows process-bound transport are
not included. HTTP/1.1 bounded non-streaming APIs
are supported; this is not an unrestricted tunnel or a general-purpose gateway.
The compatibility `allow_bearer_only` mode is off by default and must not be used
as a substitute for process binding. Every host administrator remains trusted.
