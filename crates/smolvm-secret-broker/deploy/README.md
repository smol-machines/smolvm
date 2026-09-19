# Linux service separation (not a cloud integration)

This template keeps broker administration and credentials separate from an
unprivileged desktop/agent user. The admin installs root-owned binaries/config
and systemd creates an ephemeral service identity. The agent must have **no
sudo, root access, systemd administration, or permission to change these files**.
This cannot protect against a host administrator. On a development host where
the agent has unrestricted passwordless sudo, use a separately administered host.

The root-only test `tests/service_acceptance.py` provisions the same hardening
properties in a transient service, checks HTTPS substitution, and verifies that
an ordinary host UID cannot read source credentials, runtime copies or the
broker's process environment. It stops the service and removes its fixtures.

```sh
sudo python3 -B crates/smolvm-secret-broker/tests/service_acceptance.py \
  --broker /absolute/path/to/smolvm-secret-broker \
  --observer-uid 1000 --observer-gid 1000
```

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
  "listen": "127.0.0.1:8443",
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
   start it. Only its loopback proxy endpoint and the public CA may be exposed
   to the workload. Do not widen the private directory/socket permissions to
   accommodate an isolated VMM UID; that needs a separately authorized bridge.

`LoadCredential` and the private tmpfs copies are startup snapshots. To rotate
or revoke access in this deployment, the administrator updates the root-owned
source and **restarts the service**; the old service's connections terminate.
Changing source files alone does not update the running service. Restart can
leave the outcome of an already-dispatched upstream operation unknown; do not
automatically retry non-idempotent API operations.

The standalone dotenvx integration remains available, but wrapping the broker
under the desktop user's identity is not equivalent to this separation. A
dotenvx service wrapper must run under the separate identity and protect its
decryption keys there too; that combined deployment is not validated yet.

## Remaining launch gates

Machine-specific credentials/attachment, authorization renewal on branch and
restore, fleet/control-plane wiring, full auditability and independent security
review remain outstanding. This template does not turn copyable proxy tokens
into workload identity or remove those production gates.
