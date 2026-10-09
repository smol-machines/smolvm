# Mediated egress

Mediated egress lets a Linux or macOS host decide each guest TCP flow before smolvm opens an upstream connection. The host's virtio-net gateway identifies the VM launch, destination, and up to 8 KiB of first application bytes to a loopback decider. The decider returns **allow direct**, **deny**, or **redirect**. Redirect keeps the accepted decider connection as the byte stream. smolvm does not terminate TLS or inspect HTTP.

## Configure a machine

Create a machine with ordered `egressRules`, then pass the host listener on every start:

```json
{
  "name": "worker",
  "network": true,
  "egressRules": [
    {"transport": "tcp", "cidr": "203.0.113.0/24", "ports": {"start": 443, "end": 443}, "action": "deny"},
    {"transport": "tcp", "action": "redirect"}
  ]
}
```

```json
{
  "egressInterceptor": {
    "address": "127.0.0.1:43123",
    "token": "<64 random hex digits>",
    "mediated": true
  }
}
```

Send the first body to `POST /api/v1/machines`, and the second to `POST /api/v1/machines/worker/start`. `machine start --mediated-egress --egress-interceptor 127.0.0.1:43123` is the CLI equivalent; supply its token through `SMOLVM_INTERCEPTOR_TOKEN`.

Rules are checked in order. An omitted transport, CIDR, or port range matches any value of that dimension. A redirect rule must explicitly select TCP. Invalid CIDRs or port ranges fail creation or launch. A rule's allow action connects directly, deny refuses the flow, and redirect delegates it to the bound decider. If no rule matches, the existing CIDR and DNS hostname policy applies; TCP flows that pass it reach the decider, while UDP and ICMP are denied unless a static allow rule admits them. DNS queries still pass through smolvm's host resolver and hostname filter. The platform's protected-address floor takes precedence over rules; the local loopback exception still needs an explicit allow.

The decider binding is kept in host memory. A mediated machine refuses a later start without a binding. API branches inherit their running source's binding, receive a new host-minted identity, and carry the source identity as their parent. The start response (and machine info while it runs) carries the launch identity as `mediationMachineId`, the hex form of the machine ID in each flow prelude, so a decider can map flows to machines up front; `smolvm machine start` prints it. Read decisions with `GET /api/v1/machines/worker/mediation-events`.
Portable checkpoints preserve rules and the mediator requirement, but never carry the listener token; restoring one requires a new binding at start.

## Decider protocol, version 2

One TCP connection to the loopback listener represents one guest TCP flow. All integers use network byte order. The host writes `SMOLMEG2` (8 bytes), the 32-byte host-held token, a 16-byte machine ID, a 16-byte parent ID (all zero for a root), a one-byte IP family (`4` or `6`), a two-byte destination port, 4 or 16 destination IP bytes, a two-byte initial payload length, and that many payload bytes. The token and IDs never enter the guest. The decider checks the token and returns one byte: `0` allow direct, `1` deny, or `2` redirect. With redirect, the same TCP connection becomes the data stream; the initial bytes are not replayed. A reference broker is in [`tests/mediated_egress_e2e.sh`](../tests/mediated_egress_e2e.sh).

The gateway collects the flow's opening bytes for up to 100 ms before asking: one whole TLS record (so a ClientHello split across segments still carries its SNI), the full headers of an HTTP request, or the first segment of any other protocol, capped at 8 KiB. A server-speaks-first protocol is never held longer than 100 ms. Broker connection and decision failures deny the flow. Mediated relays cap idle time at 30 minutes and total lifetime at 24 hours. The audit file rotates at 8 MiB and is exposed through the bounded events API.

## Availability

Mediated mode requires virtio-net on Linux or macOS. It is rejected with TSI, named or pod networking, and built-in credential substitution. Windows, pool workers, and embedded SDK forks do not yet have a mediated binding path; pool creation and embedded forks reject mediated sources before taking a snapshot. The API branch path is supported. The decider must bind to host loopback, and the token must be random and kept confidential because the protocol carries it on the local connection.

After building `smolvm`, run the Bash VM test on a Linux KVM or Apple Silicon macOS host with an installed agent rootfs using `bash tests/mediated_egress_e2e.sh`. The macOS script signs a temporary copy of the binary with the Hypervisor.framework entitlement.
