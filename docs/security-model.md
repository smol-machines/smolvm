# Security Model

smolvm strengthens the guest/host boundary by giving each workload a separate VM and guest kernel. It is not, by itself, a hardened multi-user control plane:

* The `smolvm` CLI and VMM processes run with the permissions of the invoking host user. That user account, the host OS, the hypervisor backend, libkrun, and smolvm are in the trusted computing base.
* Host directories passed with `--volume` are intentionally exposed to the guest with the requested access. Do not mount secrets or sensitive paths into an untrusted workload.
* Protected host configuration and log trees remain blocked by default. A trusted local workload may explicitly expose `/etc` or `/var/log` read-only below `/host` with `--allow-system-mounts` (for example, `-v /etc:/host/etc:ro`). Writable system mounts, other protected trees, and HTTP API requests remain blocked.
* `--ssh-agent` does not copy private key material into the guest, but it grants the guest access to the forwarded agent socket and therefore the ability to request signatures while the VM is running.
* Networking is disabled by default. Enabling `--net`, port forwarding, or host services expands the workload's reachable surface.
* In standalone local use, smolvm's state and control endpoints are scoped to the invoking user's environment. For hostile local co-tenants, add host-level account separation and OS confinement around the VMM process. This section does not describe the separate smolmachines cloud control plane or its tenant-isolation guarantees.
* Release archives publish SHA-256 checksums and the installer rejects a mismatch when the checksum file is available. Releases are not currently signed or accompanied by provenance attestations, and the installer permits installation when the checksum file cannot be downloaded.

Treat root in the guest as untrusted. The VM boundary limits its direct access to the host, while every explicitly forwarded capability, including mounts, network access, ports, and SSH agent access, becomes part of the workload's authority.
