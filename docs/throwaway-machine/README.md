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
workload's machine then starts from it with no network. On macOS arm64 on v1.22.2,
`smolvm machine run --image busybox` with no `--net` pulled the image and the workload's `wget`
printed `bad address 'example.com'`. The output above is Linux aarch64 on the same release, on a
host where that helper could not boot and the run fell back to pulling in the guest. `machine run`
is unchanged on v1.23.0: on macOS arm64 it printed the same `bad address`, and with
`SMOLVM_IMAGE_SEEDS=0` it stopped at the pull with the hint above.

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
`--oci-cache` flag serves the same purpose on a host that runs the same image repeatedly.

## Grant egress one host at a time

`--allow-host <HOSTNAME>` resolves the name at VM start and permits that name **and its
subdomains**; `--allow-host-pattern <HOSTNAME>` permits the exact name only, and `'*.domain'` the
subdomains without the apex. `--allow-cidr <CIDR>` permits an address range. All three imply
`--net`. There is no
deny-list: a job that needs broad access needs host or fleet controls as well.

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
10.200.0.0/30` moves the link. It implies `--net`, so it is a grant in its own right.

`--allow-host-loopback` is a separate grant, off by default, that lets the guest reach services on
the host's own loopback. Leave it off for untrusted code: it is what stands between an isolated
run and your local database, your Docker socket and your debuggers. Cloud metadata stays blocked
either way.

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

## Stopping a run is not Ctrl-C

From v1.20.2 interrupting the CLI ends its VM. Interrupting a script that runs the CLI in the
background, as the packet's own `run.sh` does, or the CLI of a cached run on an older release, can
leave the VM alive with its workload still running. The packet's `scripts/cleanup.sh --cancel` is
the cancel; `SKILL.md` and `references/traps.md` carry the measurements and what each host does.

## Platforms

The offline shape this packet is built on works on macOS from v1.20.2 and not before;
`references/macos.md` gives older releases a route that does and says what it costs. On Windows
the bake never completes, so the offline shape is unavailable there for a different reason:
`references/windows.md`.
