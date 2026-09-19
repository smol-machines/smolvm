# Desktop applications, secrets in a gateway VM

Keep using your desktop agent. Run dotenvx and the credential broker inside a
dedicated Smol machine; point the local application at its proxy. Only approved
requests receive real credentials, and the credentials stay in the gateway.

**Separate administration matters.** If the desktop agent can execute commands
inside the gateway, read its disks or administer its VM, it can read the secrets.
Use a separate administrator identity with protected Smol state. Host root/sudo
remains trusted. A VM owned by the same unrestricted desktop user is a convenience,
not protection from that user. Do not grant the agent gateway administration.

## Gateway administrator

Run these under the gateway administrator account, not the desktop agent account:

```sh
smolvm machine create --name credential-gateway --image ubuntu:24.04 --net \
  --cpus 1 --mem 768 --storage 3 --overlay 1 \
  --expose-socket /run/credential-gateway/proxy.sock
smolvm machine start --name credential-gateway
```

Inside the gateway, install a Linux broker binary matching the guest architecture,
dotenvx and the supplied `smolvm-credential-gateway` launcher in `/usr/local/bin`.
The desktop's OS is not the binary's target. Make the binaries executable.

Provision `/etc/credential-gateway` as a private directory (0700), with these
administrator-owned files (0600):

- `.env` and `.env.keys`: dotenvx-encrypted secrets and their decryption keys.
- `access`: a random proxy capability, distinct from every upstream credential.
- `server-chain.pem` and `server.key`: a certificate covering the approved API
  hostname and its private key. Give the desktop only the public CA certificate.
- `config.json`:

```json
{
  "listen": null,
  "unix_socket": "/run/credential-gateway/proxy.sock",
  "allow_bearer_only": true,
  "certificate": "/etc/credential-gateway/server-chain.pem",
  "private_key": "/etc/credential-gateway/server.key",
  "access_token_file": "/etc/credential-gateway/access",
  "grants": [{
    "host": "api.example.com",
    "placeholder": "SMOL_PLACEHOLDER_EXAMPLE_KEY",
    "header": "authorization",
    "methods": ["GET", "HEAD"],
    "secret_env": "EXAMPLE_API_KEY"
  }]
}
```

Here capability authorization is deliberate: the client stays on the desktop,
so the gateway cannot authenticate it as a local VMM process. Protect and scope
the capability. Do not expose an unauthenticated or plaintext public proxy.

Start the gateway and an administrator-owned localhost bridge:

```sh
smolvm machine exec --name credential-gateway --detach -- \
  /usr/local/bin/smolvm-credential-gateway

gateway_dir=$(smolvm machine data-dir --name credential-gateway)
socat TCP4-LISTEN:7443,bind=127.0.0.1,reuseaddr,fork \
  UNIX-CONNECT:"$gateway_dir/proxy.sock"
```

No credential directory or workspace is mounted into the gateway. Keep the
bridge under administrator supervision; restart the launcher after a VM restart.
The launcher is not a supervisor and `--detach` does not automatically restart it.

## Desktop application

The administrator supplies a proxy capability and public CA, not `.env.keys` or
real API keys. Configure the application, without wrapping or relocating its agent:

```sh
export EXAMPLE_API_KEY=SMOL_PLACEHOLDER_EXAMPLE_KEY
export https_proxy=http://smol:PROXY_CAPABILITY@127.0.0.1:7443
export CURL_CA_BUNDLE=/path/to/gateway-public-ca.pem
curl -H "Authorization: Bearer $EXAMPLE_API_KEY" https://api.example.com/user
```

Applications must honor the proxy and trust the gateway CA. Other runtimes have
their own CA settings; certificate-pinned clients are not supported. This does
not automatically configure desktop editors or intercept their tool execution.

The administrator can remove/rotate `access` inside the gateway to revoke future
requests. Updating encrypted secrets requires restarting the broker. A stopped
gateway fails closed; no real-key fallback exists on the desktop. Revocation
cannot undo requests already sent upstream.

HTTP limits and method restrictions are the same as the broker's. The capability
permits actions, not key retrieval; use narrowly scoped upstream credentials.
Gateway disks and any exports contain secret material and must remain private.

This workflow is implemented locally. Automated Smol Cloud deployment and secure
remote transport provisioning are not implemented; do not publish this localhost
bridge on a public interface as a substitute.
