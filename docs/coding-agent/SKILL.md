---
name: coding-agent
description: Runs a coding agent (Claude Code, OpenCode, Codex or any other) inside a persistent smolvm machine with the project mounted, so it can run with full permissions without touching the host. Use when someone wants to sandbox their coding agent, run it in skip-permissions or YOLO mode safely, or give it a disposable environment it can install anything into. Do not use it to run untrusted code with no network; use throwaway-machine for that.
---

# A coding agent in a machine

Verified on **smolvm v1.34.0** on macOS arm64 and on Linux x86_64, 2026-11-09, and on **v1.27.4**
on Linux x86_64, 2026-10-14. Done means the agent runs inside the
machine from the project directory, its edits appear on the host, and git works on the mounted
repo.

## Procedure

**1. Copy the Smolfile into the project.** Edit the `npm install` line in `init` to the agents you
use; any install command works.

```bash
cp docs/coding-agent/assets/agent.smolfile ./Smolfile
```

**2. Create and start the machine.** Pass API keys as references so they are read from your host
at launch, never written to the machine record:

```bash
smolvm machine create --name agent -s Smolfile --secret-env ANTHROPIC_API_KEY=ANTHROPIC_API_KEY
smolvm machine start --name agent      # first start runs init: under a minute once the image is pulled
```

The Smolfile forwards your SSH agent, so `start` needs `SSH_AUTH_SOCK` set on the host: without it,
it stops with `ssh-agent: SSH_AUTH_SOCK is not set`. Start one with `eval $(ssh-agent)`, or delete
the `[auth]` block.

**3. Run the agent.**

```bash
smolvm machine exec --name agent -it -- claude --dangerously-skip-permissions
smolvm machine exec --name agent -it -- opencode
```

`machine shell --name agent` gives a shell in `/workspace` for anything else.

**4. Check git.** `smolvm machine exec --name agent -- git status` must print the repo's status,
not `dubious ownership`; if it does not, the `safe.directory` line in `init` did not run.

**5. Stop or delete.** `machine stop --name agent` keeps the installed agents for next time, and the
next start takes about a second. `machine delete --name agent -f` removes the machine; the project
stays on the host.

## Notes

- `init` runs once. Changing it later needs a new machine, or run the new commands with `exec`.
- To keep the agent off your LAN and the host's ports, add `block_private = true` under
  `[network]` (from v1.28.1). See `README.md`.
- An agent that needs Docker: add `"/var/lib/docker", "/var/lib/containerd"` to `[dev] volumes`
  (from v1.28.1) and see [docker-in-machine](../docker-in-machine/README.md).

## Re-verified on v1.34.0

Run 2026-11-09 PT against v1.34.0 from the published release, checksum checked, under a fresh
isolated `HOME` on macOS 27.2 arm64 (Apple M4), twice, the second time from a fresh `HOME`, and once
on Lima `linux-kvm` (Ubuntu 24.04 aarch64, 11 GiB). On macOS every step, twice: first start 33 and
36 s, restart 0 s, Claude Code 2.1.321, OpenCode 1.19.5, `git status` clean of `dubious ownership`,
an edit in the guest on the host, the throwaway SSH key listed. On Linux the 4096 MiB machine did
not boot inside 30 s on this 11 GiB host.

On Linux x86_64 (Ubuntu 22.04, KVM, an NVIDIA A10 cloud host with 30 cores and 222 GiB), twice on
2026-11-09, each pass from a fresh `HOME`, every step: first start 30 s, restart 1 s, Claude Code
2.1.321, OpenCode 1.19.5, `git status` clean of `dubious ownership`, an edit in the guest on the
host, the throwaway SSH key listed.
