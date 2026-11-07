# Security Model

smolvm strengthens the guest/host boundary by giving each workload a separate VM and guest kernel. It is not, by itself, a hardened multi-user control plane:

* The `smolvm` CLI and VMM processes run with the permissions of the invoking host user. That user account, the host OS, the hypervisor backend, libkrun, and smolvm are in the trusted computing base.
* Host directories passed with `--volume` are intentionally exposed to the guest with the requested access. Do not mount secrets or sensitive paths into an untrusted workload.
* Protected host configuration and log trees remain blocked by default. A trusted local workload may explicitly expose `/etc` or `/var/log` read-only below `/host` with `--allow-system-mounts` (for example, `-v /etc:/host/etc:ro`). Writable system mounts, other protected trees, and HTTP API requests remain blocked.
* `--ssh-agent` does not copy private key material into the guest, but it grants the guest access to the forwarded agent socket and therefore the ability to request signatures while the VM is running.
* `--waypipe` opens a vsock channel from the guest to a host Unix socket that a `waypipe client` reads next to your Wayland compositor. A guest with it enabled can drive that client; enable it only for workloads whose GUI you mean to display.
* `--x11` connects the guest straight to your host X server. X11 isolates clients weakly, so treat a guest with `--x11` as having the whole X server (input, other windows, clipboard); enable it only for trusted GUI workloads, and use X access control (`xhost`) deliberately.
* Networking is disabled by default. Enabling `--net`, port forwarding, or host services expands the workload's reachable surface.
* In standalone local use, smolvm's state and control endpoints are scoped to the invoking user's environment. For hostile local co-tenants, add host-level account separation and OS confinement around the VMM process. This section does not describe the separate smolmachines cloud control plane or its tenant-isolation guarantees.
* Release archives publish SHA-256 checksums and the installer rejects a mismatch when the checksum file is available. Releases are not currently signed or accompanied by provenance attestations, and the installer permits installation when the checksum file cannot be downloaded.

## Corporate proxy and TLS inspection

`--use-host-proxy` passes the host's `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`
and `NO_PROXY` (on macOS, the system proxy; PAC files are refused) to the
workload and to the image pull. A proxy on `127.0.0.1` is rewritten to the
host's outbound address, so it must also listen on a non-loopback address.
`localhost,127.0.0.1,::1` are always in `NO_PROXY`.

`--trust-host-certs` mounts the host's trusted roots read-only at
`/etc/smolvm-host-trust/ca-bundle.pem` and points `SSL_CERT_FILE`,
`REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `GIT_SSL_CAINFO` and similar at
it, so a corporate TLS-inspection root works in the image pull and the
workload. `SMOLVM_HOST_CA_BUNDLE` selects another bundle. It cannot be combined
with `--credential` yet.

```sh
smolvm machine run --net --use-host-proxy --trust-host-certs --image alpine -- wget -qO- https://example.com
```

Both widen what the machine trusts to what the host trusts; `-e` values still win.

## Unix socket bridges

`--expose-socket GUEST[:HOST]` makes a socket the workload listens on reachable
on the host, at `HOST` or at `<basename>` in `smolvm machine data-dir --name
NAME`. `--mount-socket HOST:GUEST` puts a host socket at `GUEST` in the
machine. Both repeat (up to 64), take absolute guest paths, and are CLI-only.
`docker_socket = true` in a Smolfile is the fixed form for
`/var/run/docker.sock`.

```sh
smolvm machine create --name app --image alpine \
  --mount-socket /run/user/1000/podman/podman.sock:/run/podman.sock \
  --expose-socket /run/app.sock:/tmp/app.sock
```

Any host process that can open an exposed socket reaches the guest service, and
the guest gets whatever authority the mounted host socket carries.

## Guest root

Treat root in the guest as untrusted. The VM boundary limits its direct access to the host, while every explicitly forwarded capability, including mounts, network access, ports, and SSH agent access, becomes part of the workload's authority.
