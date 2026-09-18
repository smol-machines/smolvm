# smolvm-network

The **host-side userspace network backend** for smolvm's virtio-net path.
It connects guest Ethernet traffic to host sockets through a smoltcp-based
gateway and the libkrun frame bridge.

This crate is intended for runtime integrators. It is not a standalone VPN,
container network manager, or VM launcher. Most users should configure networking
through the [smolvm runtime](https://github.com/smol-machines/smolvm#readme).

## Add to your project

```sh
cargo add smolvm-network
```

## Configure an egress policy

```rust
use smolvm_network::EgressPolicy;
use std::net::{IpAddr, Ipv4Addr};

fn main() {
    let allowed = vec!["203.0.113.0/24".to_string()];
    let policy = EgressPolicy::from_allowed_cidrs(Some(&allowed));
    assert!(policy.is_restricted());
    assert!(!policy.allows(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))));
}
```

This example only constructs and queries a policy. It neither connects a guest
nor installs a host firewall. The runtime must apply the policy to traffic.

## How traffic flows

Guest kernel → virtio-net → libkrun frame bridge → shared frame queues →
smoltcp gateway → host sockets.

The crate includes:

- Frame transport and queues between the VM bridge and network runtime.
- TCP and UDP relays, DNS forwarding, and published TCP port handling.
- CIDR/hostname egress-policy support.
- Linux-specific network-namespace/TAP integration.

See `VirtioNetworkRuntime` and its configuration types for embedding. A working
integration must supply the compatible VM-side frame transport and manage the
runtime lifecycle; adding this dependency alone does not enable networking.

## Scope and security

This backend is distinct from smolvm's TSI networking path. Availability depends
on the host and runtime configuration; do not infer that every smolvm platform
supports virtio-net from this library's API.

An allowlist is one layer of enforcement, not a complete sandbox. Configure
appropriate host/guest isolation and protect credentials separately.

## Links

[API documentation](https://docs.rs/smolvm-network) · [crates.io](https://crates.io/crates/smolvm-network) · [Source](https://github.com/smol-machines/smolvm/tree/main/crates/smolvm-network)

Part of [Smol Machines](https://github.com/smol-machines/smolvm). Licensed under Apache-2.0.
