# Sandboxing untrusted code

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
| Branch | clones a running machine with copy-on-write RAM and disk | many short workers from one warm state |

## The network is off unless you ask for it

`--net` enables outbound access; without it the guest has none. The pull happens **inside the
guest**, so a machine built from a registry image needs `--net` even when the workload itself
needs no egress:

```console
$ smolvm machine run --image alpine -- nslookup example.com
Error: agent operation failed: pull image: ... dial udp 1.1.1.1:53: connect: network is unreachable
```

To run a workload with no network at all, fetch the image once with the network on, then take it
away before the run that matters. The `--oci-cache` flag serves the same purpose on a host that
runs the same image repeatedly.

## Grant egress one host at a time

`--allow-host <HOSTNAME>` resolves the name at VM start and permits only that destination;
`--allow-cidr <CIDR>` does the same for an address range. Both imply `--net`. There is no
deny-list: a job that needs broad access needs host or fleet controls as well.

```console
$ smolvm machine run --net --image alpine --allow-host registry.npmjs.org -- \
    wget -q -O /dev/null https://registry.npmjs.org
                                              # allowed
$ smolvm machine run --net --image alpine --allow-host registry.npmjs.org -- \
    wget -q -O /dev/null https://google.com
wget: bad address 'google.com'                # not in the allow list
```

`--allow-host-loopback` is a separate grant, off by default, that lets the guest reach services on
the host's own loopback. Leave it off for untrusted code: it is what stands between a sandbox and
your local database, your Docker socket and your debuggers. Cloud metadata stays blocked either
way.

## Mounts are authority

A mount deliberately exposes a host directory to guest code. Mount the repository read-only and
give generated output its own writable directory, so a test that writes into its source tree
fails loudly instead of editing yours.

## Stopping a run is not Ctrl-C

An interrupted run can leave the VM alive with its workload still running. The topic's
`scripts/cleanup.sh --cancel` is the cancel; `SKILL.md` and `references/traps.md` carry the
measurements and what each host does.

## Platforms

The offline shape this topic is built on does not work on macOS; `references/macos.md` gives a
route that does and says what it costs. On Windows the bake never completes, so the offline shape
is unavailable there for a different reason: `references/windows.md`.
