# Running untrusted code in a throwaway machine

Run a program you do not trust inside a hardware-isolated microVM, against a repository it must
not modify, with no network unless you grant it, and collect what it produced from a directory you
chose. The host filesystem, the network and your credentials are on the other side of a hypervisor
boundary.

`SKILL.md` is the procedure an agent follows, with the traps that cost the most time.
`scripts/` holds the five scripts it runs.

## Choose the lifecycle first

| Mode | Behaviour | Use it for |
|---|---|---|
| Ephemeral run | creates a machine, runs one command, deletes it | untrusted scripts, CI jobs, one agent turn |
| Persistent machine | keeps disk state across stop and start | debugging a job you need to inspect afterwards |
| Pack | prebuilds dependencies into a portable artifact | the same job repeated on compatible hosts |
| Branch | starts children from a running machine's memory and disk, copy-on-write ([branching](../branching.md)) | many short workers from one warm state |

## The image decides the C library and the tools

Read from each image on v1.23.1 on macOS arm64 with

```bash
smolvm machine run --image <image> -- sh -c 'ldd --version 2>&1 | head -1; for c in apk apt-get python3 pytest; do command -v $c; done'
```

| Image | C library | Package manager | `python3` | `pytest` |
|---|---|---|---|---|
| `alpine` | musl | `apk` | no | no |
| `python:3.12-alpine` | musl | `apk` | yes | no |
| `python:3.12-slim` | glibc 2.41 (Debian) | `apt-get` | yes | no |
| `debian:bookworm-slim` | glibc 2.36 | `apt-get` | no | no |
| `ubuntu:24.04` | glibc 2.39 | `apt-get` | no | no |

None of them has `pytest`. `smolvm machine run --image python:3.12-slim -- pytest` exits 255 with
``executable file `pytest` not found in $PATH``, so a test command installs its runner first, which
needs the network for that step.

## The network is off unless you ask for it

`--net` enables outbound access; without it the guest has none. Where a registry image is pulled
decides whether a run without `--net` can start. When the pull happens **inside the guest**, a run
from a registry image needs `--net` even when the workload itself needs no egress:

```console
$ smolvm machine run --image busybox -- true
Error: agent operation failed: pull image: ... dial udp 1.1.1.1:53: connect: network is unreachable
Hint: networking is disabled. Add --net to enable image pulls:
```

From v1.22.0 a run first builds a shared seed of the image in a helper machine of its own, and the
workload's machine then starts from it with no network: on macOS arm64 on v1.22.2, v1.23.0 and
v1.29.0, `smolvm machine run --image busybox` with no `--net` pulled the image and the workload's
`wget` printed `bad address 'example.com'`. The output above is Linux aarch64 on v1.22.2, where the
helper could not boot and the run fell back to pulling in the guest; on macOS
`SMOLVM_IMAGE_SEEDS=0` stops at the pull with the same hint.

**A persistent machine is where v1.23.0 differs.** Through v1.22.2 `machine create` with a registry
image and no network is refused up front. From v1.23.0
([#1536](https://github.com/smol-machines/smolvm/pull/1536)) it is accepted, and `machine start`
fetches the image on the host and boots it with no network in the guest:

```bash
smolvm machine create --name smolskill-box --image python:3.12-alpine \
    --volume "$PWD/repo:/workspace:ro" --volume "$PWD/out:/out" -- sh -c 'while true; do sleep 3600; done'
smolvm machine start --name smolskill-box
smolvm machine exec --name smolskill-box -- sh -c 'python3 /workspace/calc.py > /out/result.txt'
smolvm machine stop --name smolskill-box
smolvm machine delete --name smolskill-box --force
```

On macOS arm64 on v1.23.0 the start took 1.8 s, `machine ls --json` showed `network` false, and
inside the guest a write to `/workspace` gave `Read-only file system` and a fetch `Try again`. On
Linux aarch64 the start took 12 s and the guest gave the same two refusals.
The machine persists until deleted, so it does not have the throwaway property.

Before v1.23.0, to run a workload with no network at all, fetch the image once with the network on,
then take it away before the run that matters (`references/macos.md`, first choice). The
`--oci-cache` flag serves the same purpose on a host that runs the same image repeatedly, except on
macOS from v1.24.0 ([#1819](https://github.com/smol-machines/smolvm/issues/1819)).

## Grant egress one host at a time

`--allow-host <HOSTNAME>` resolves the name at VM start and permits that name **and its
subdomains**; `--allow-host-pattern <HOSTNAME>` permits the exact name only, and `'*.domain'` the
subdomains without the apex. `--allow-cidr <CIDR>` permits an address range. All three imply
`--net`, and can be combined and used more than once. `--net` alone opens full outbound TCP, UDP and
DNS, and `--outbound-localhost-only` limits egress to `127.0.0.0/8` and `::1`, also implying `--net`.
In a Smolfile, `[network] allow_host_patterns` takes the exact and wildcard forms and `allow_hosts`
the `--allow-host` one. There is no per-host deny-list flag, and `--block-private` denies private
ranges only: a job that needs broad access needs host or fleet controls as well.

From v1.28.1, `--block-private` blocks private, internal and link-local destinations (the LAN,
cloud metadata, CGNAT, the host's loopback) while the public internet stays open, and implies
`--net`. `--allow-private <CIDR>` re-opens one private range under it, such as an internal registry,
and can be used more than once. In a Smolfile they are `[network] block_private = true` and
`allow_private = ["10.20.0.0/16"]`. On macOS arm64 on v1.29.0, a web server on the host's LAN
address was reachable with `--net`, blocked with `--block-private`, and reachable again with
`--allow-private <that address>/32`, while `example.com` stayed reachable throughout.

`--allow-host` and a credential's host do not re-open a private address under `--block-private`: a
name that resolves into a private range stays unreachable until `--allow-private` covers it.
`machine create`, `run` and `start` print a warning that names the host, its addresses and the
`--allow-private` range to add.

`--deny-cidr <CIDR>` refuses a range before anything is allowed. `--allow-udp
<CIDR>[:<PORT>[-<END>]]` admits UDP to a range, on every port or only the ones named, such as
`--allow-udp 1.1.1.1:123` for NTP or `--allow-udp 192.0.2.0/24:3478-3480` for a TURN relay; write
an IPv6 range with a prefix or in brackets (`[2001:db8::1]:443`). A machine started with an
external egress interceptor denies every datagram but DNS, and `--allow-udp` is how it reaches a
UDP service anyway. A deny CIDR still wins over it, cloud metadata stays blocked, `--block-private`
keeps private ranges closed unless `--allow-private` re-opens them, and DNS on port 53 keeps its own
path. It implies `--net`, the Smolfile form is `[network] allow_udp`, and `machine update
--allow-udp` / `--remove-allow-udp` change it, live on a machine started with an allow list, as
`--allow-cidr` does.

```console
$ smolvm machine run --net --image alpine --allow-host registry.npmjs.org -- \
    wget -q -O /dev/null https://registry.npmjs.org
                                              # allowed
$ smolvm machine run --net --image alpine --allow-host registry.npmjs.org -- \
    wget -q -O /dev/null https://google.com
wget: bad address 'google.com'                # not in the allow list
```

A guest that runs Tailscale or another carrier NAT VPN claims `100.64.0.0/10`, which contains the
link a grant puts it on, `100.96.0.0/30`, and loses its gateway and resolver. `--guest-subnet
10.200.0.0/30` moves the link: the gateway and resolver take `.1` and the guest `.2`, on virtio-net.
It implies `--net`, so it is a grant in its own right. Over the API it is `guestSubnet` on create,
and it cannot be combined with `--network`, since a named network assigns member addresses itself.

`--allow-host-loopback` is a separate grant, off by default, that lets the guest reach services on
the host's own loopback. Leave it off for untrusted code: it is what stands between an isolated
run and your local database, your Docker socket and your debuggers. Cloud metadata stays blocked
either way.

### Request rules

`--allow-request SPEC` and `--deny-request SPEC` narrow what a machine may send to a host over
HTTPS. A `SPEC` is `[METHODS ]HOST[/PATH-GLOB]`: `METHODS` is comma-separated and case-insensitive
(default: every method), `HOST` is an exact name or `*.domain` (subdomains only, not the apex, like
`--allow-host-pattern`), and the path glob defaults to every path. In a glob, `*` is one whole
segment and `**` is zero or more segments; a rule path with `*` inside a segment or with `%` is
refused (write it decoded), and the query is ignored. Both flags can be repeated.

```console
$ smolvm machine run --net --image curlimages/curl --allow-host httpbin.org \
    --allow-request 'GET httpbin.org/get' -- curl -s https://httpbin.org/post
smolvm: request denied by request rules (no allow rule matches)     # HTTP 403
```

A host with any allow rule needs a match, any matching deny refuses, and a deny wins. Hosts with no
rules are unchanged. A rule never makes a host reachable (`--allow-host` and the other grants still
decide) and does not imply `--net`. A request is matched on its canonical path: percent-decoded
(`%2F` splits a segment), `.` and `..` resolved without rising above the root, repeated slashes
collapsed. A refused request gets a `403` with a one-line reason. `machine egress-events` lists it
as a `request` with its method and URL (without the query), and the host log records the machine,
host, method, path and reason.

Rules apply to HTTPS on port 443 only; plain HTTP follows separately. The machine CA covers rule
hosts as it covers credential hosts, and the guest trusts it automatically (see
[credential substitution](../credential-substitution.md)). An allowed request on a credential host
still has its credential substituted. A machine with rules refuses TLS connections that send no
server name. A guest that sends the name of an allowed host without rules while addressing a ruled
one (domain fronting) is not caught: servers route on the name, and most CDNs refuse it.

A host named by any rule, even a deny-only one, goes through the interceptor, so the guest speaks
HTTP/1.1 to it, WebSocket upgrades get `426`, and request bodies are buffered and capped at 8 MiB
(`413`); see [backends and limits](../credential-substitution.md#backends-and-limits). A machine
with rules drops guest UDP to port 443, so HTTP/3 (QUIC) cannot skip them and clients fall back to
TCP; an `--allow-udp` rule covering the destination and port 443 re-opens it. Plain HTTP and other
TCP ports to a ruled host are not covered, and origin-side normalizations are not mirrored (double
encoding, `;params`, backslashes, case-insensitive paths): rules are a guard rail against mistakes,
not a boundary against a hostile workload.

Prefer allow rules where a host must be pinned down. An allow rule fails closed: a path spelled in
a way the matcher does not recognize gets a `403`. A deny rule is best-effort: a spelling the origin
accepts and the matcher reads differently goes through.

In a Smolfile, each rule is a `[[network.requests]]` table (see [Smolfile](../smolfile.md)); CLI
flags extend its list. Over the API it is the `requestRules` array on machine create, with objects
of `action` (`allow` or `deny`), `hosts`, `methods` and `paths`. `pack create -s` drops request
rules. They are refused together with an external egress interceptor, with `--net-backend tsi`
(at start: only virtio-net drops QUIC) and when restoring a checkpoint, and `machine update` cannot
change them yet.

A release older than the one that added request rules cannot read the record of a machine that has
them, and its commands fail until that machine is gone. Delete such machines with the newer build
before downgrading. Machines without rules are unaffected.

`./tests/run_tests.sh request-rules` checks all of this against a live machine. It needs internet
access to httpbin.org and is skipped without it.

## Publishing ports

`-p HOST:GUEST` forwards a host TCP port to the machine. The server inside must listen on
`0.0.0.0`, not `127.0.0.1`: a server bound only to the guest's loopback is unreachable from the
host, and connections are reset. `machine status` shows each published port's listening state.
Publishing a port gives no outbound access: without `--net` or an allow list the machine serves
inbound connections only.

`-p HOST:GUEST/udp` forwards a UDP port, for game servers, voice and other datagram services.
Each remote client gets its own session: the guest sees it as a distinct gateway address and
port, and its replies reach that client from the published host port. A session ends after two
minutes of silence. Datagrams up to 1472 bytes pass; larger ones are dropped, since the gateway
does not fragment. TCP and UDP may publish the same host port number. A branch gets fresh host
ports for its source's UDP forwards and prints them; `--port` on a branch pins TCP ports only.

## Mounts are authority

A mount deliberately exposes a host directory to guest code, as the
[security model](../security-model.md) says of every forwarded capability. Mount the repository
read-only and give generated output its own writable directory, so a test that writes into its
source tree fails loudly instead of editing yours.

Never mount `/`, `$HOME` or `~/.ssh` into a machine running untrusted code. Read-only does not
protect a secret: on v1.23.1 a guest given `-v "$HOME/.ssh:/mnt/ssh:ro"` listed the key files and
printed `-----BEGIN OPENSSH PRIVATE KEY-----` from the private one (a dummy key in a scratch
`HOME`).

Leave `--ssh-agent` off unless the work needs your SSH identity. The key stays on the host, but any
process in the guest can ask the agent to sign with it: with a dummy key loaded,
`smolvm machine run --net --ssh-agent --image alpine -- sh -c 'apk add -q openssh-client && ssh-add -l'`
listed its fingerprint from inside the guest.

## Stopping a run

From v1.20.2 interrupting the CLI ends its VM, and the packet's `run.sh` forwards Ctrl-C and
`SIGTERM` to the CLI it runs in the background. A script that backgrounds the CLI without
forwarding, or the CLI of a cached run on an older release, can leave the VM alive with its
workload still running; the packet's `scripts/cleanup.sh --cancel` is the cancel there. `SKILL.md`
and `references/traps.md` carry the measurements and what each host does.

## Platforms

The offline shape this packet is built on works on macOS from v1.20.2 through v1.23.7. From v1.24.0
(measured through v1.29.0) no `--oci-cache` run boots on macOS
([#1819](https://github.com/smol-machines/smolvm/issues/1819)), so it is unavailable there again,
as `SKILL.md` says; before v1.20.2 `references/macos.md` gives a route that does and says what it
costs. On Windows
the bake never completes, so the offline shape is unavailable there for a different reason:
`references/windows.md`.
