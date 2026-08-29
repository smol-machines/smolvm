# Host-side egress proxy

smolvm can transparently route a VM's outbound TCP and DNS traffic through an
unauthenticated SOCKS5 listener on the host. Applications inside the guest use
ordinary sockets: no `HTTP_PROXY`, `HTTPS_PROXY`, or `ALL_PROXY` variables are
injected, and the proxy address and upstream credentials do not enter the VM.

This is intended for a host-local proxy such as Mihomo or sing-box. Configure
remote-provider authentication in that proxy, then give smolvm only its
loopback listener:

```bash
smolvm machine run --image alpine \
  --egress-proxy socks5://127.0.0.1:7891 \
  -- wget -qO- https://api.ipify.org
```

`--egress-proxy` implies `--net` and selects `virtio-net`. An explicit
`--net-backend tsi` is rejected because TSI connections do not pass through the
host-side virtio network stack.

## Persistent machines

The endpoint is stored as non-secret machine configuration:

```bash
smolvm machine create --name proxied \
  --image alpine \
  --egress-proxy socks5://127.0.0.1:7891

smolvm machine start --name proxied
smolvm machine exec --name proxied -- wget -qO- https://api.ipify.org
```

Change or remove it without rebuilding the machine disk:

```bash
smolvm machine update --name proxied \
  --egress-proxy socks5://127.0.0.1:7892

smolvm machine update --name proxied --clear-egress-proxy
```

Restart a running machine after `machine update` so the new host network
transport is installed for that boot.

## Smolfile

```toml
[machine]
image = "alpine"

[network]
egress_proxy = "socks5://127.0.0.1:7891"
```

## Traffic and failure semantics

- Guest TCP connections use SOCKS5 CONNECT through the configured listener.
- Guest DNS packets are intercepted by the virtio gateway and sent to the
  configured resolver with SOCKS5 UDP ASSOCIATE. Host DNS is not consulted.
- Other UDP and external ICMP are blocked while the proxy is required. Gateway
  control traffic remains local to smolvm.
- A refused connection, failed handshake, unavailable UDP association, or DNS
  timeout is returned to the guest as a network failure. smolvm never retries
  the request directly.
- Only `socks5://IP:PORT` is accepted. Hostnames and credentials are rejected to
  avoid bootstrap DNS and secret persistence. Put remote proxy credentials in
  the host proxy instead.

The SOCKS5 listener must support both CONNECT and UDP ASSOCIATE. Mihomo mixed or
SOCKS listeners support both when UDP is enabled. The host proxy remains
responsible for routing policy—for example, selecting a remote node, direct
domestic routes, DNS policy, and provider credentials.

## Current scope

The option is supported by `machine run`, `machine create`, `machine update`,
and Smolfiles on the virtio-net backend. It is not embedded into packed
`.smolmachine` executables; requests that would silently bypass the configured
proxy are rejected.
