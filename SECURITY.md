# Security Policy

smolvm runs untrusted workloads inside per-workload microVMs, each with its own
guest kernel. The boundary we defend is guest to host: guest code should not be
able to affect the host beyond the resources, mounts, and network it was
explicitly given.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report privately via GitHub's
**[Private vulnerability reporting](https://github.com/smol-machines/smolvm/security/advisories/new)**
(repo → **Security** → **Report a vulnerability**). The report stays private
between you and the maintainers, and we will coordinate a fix and a disclosure
timeline with you there.

Please include:

- the affected component (CLI, VMM, guest agent, containerd shim, pack/image
  handling) and the version or commit,
- a description and, where possible, a minimal reproduction,
- the host OS and backend (macOS Hypervisor.framework, or Linux KVM),
- the impact you believe it has.

## In scope

- **Guest to host escape** — guest code reading, writing, or executing on the
  host beyond its configured mounts, network, and devices.
- **Boundary failures in the host-side components** — the VMM process, the boot
  helper, the guest agent transport, or the containerd shim.
- **Crafted input that escapes its handler** — a `.smolmachine` pack or an OCI
  image that reaches outside its extraction root or runs code on the host.
- **Isolation between workloads** — one VM reaching another VM's state, disks,
  or control socket under the same user.
- **Release integrity** — a tampered artifact that the installer's checksum
  verification should reject and does not.

## Out of scope

These follow from the security model in the [README](README.md); they are
design, not defects.

- Anything reached only through a capability the user explicitly forwarded, and
  behaving as documented: `--volume` mounts, `--ssh-agent`, `--net`, and
  published ports all widen the workload's authority on purpose.
- Anything that presupposes an already-compromised host, or a hostile
  local user on the host. The invoking user account, the host OS, the
  hypervisor backend, and libkrun are inside the trusted computing base.
- Guest-internal behaviour with no host effect. Root in the guest is untrusted
  by design.
- Limitations already documented in the README security model, including
  unsigned release archives. Improvements there are welcome as normal issues.
- The hosted cloud service, which is operated separately from this repo.

## Supported versions

Only the latest published release is supported. Please reproduce against it
before reporting.

## What you can expect

- We practice coordinated disclosure, and will agree a timeline with you before
  anything is published.
- We credit reporters in the advisory unless you ask us not to.
- We will not pursue legal action over good-faith research that follows this
  policy.
