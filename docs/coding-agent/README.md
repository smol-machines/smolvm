# A coding agent in a machine

Run Claude Code, OpenCode, Codex or any other coding agent inside a machine, with full
permissions, so it can install packages, run anything and break things without touching your host.
The machine is the boundary, so the agent does not need to ask before each command.

`SKILL.md` is the procedure and `assets/agent.smolfile` the machine definition. Nothing in smolvm
is specific to one agent: the Smolfile installs whichever ones you list, and the rest is ordinary
machine configuration.

## What the Smolfile sets up

| Need | How |
|---|---|
| The agent edits your project | `.:/workspace` mounts the directory holding the Smolfile; edits appear on the host immediately, owned by your host user |
| It can install and download | `net = true`; tighten with `[network] block_private = true` (see below) |
| Installs happen once | `init` runs on the first start only; later starts take about a second |
| git and ssh with your keys | `[auth] ssh_agent = true` forwards the host agent; keys never enter the machine |
| An API key | `--secret-env ANTHROPIC_API_KEY=ANTHROPIC_API_KEY` at create, or `--credential` so the guest only ever sees a placeholder ([credentials](../credentials/README.md)) |

## Two things that fail without the Smolfile's fixes

**git refuses the mounted repo.** The agent runs as root in the machine and the repo belongs to
your host user, so git stops with `fatal: detected dubious ownership in repository at
'/workspace'`. The Smolfile's `git config --system --add safe.directory '*'` fixes it.

**Claude Code refuses its skip-permissions mode as root.** `claude
--dangerously-skip-permissions` prints `cannot be used with root/sudo privileges for security
reasons`. `IS_SANDBOX=1` in the machine's environment tells it it is in a sandbox, and the flag is
accepted.

## Keeping the agent off your network

`net = true` gives the agent everything your host can reach, including your LAN, a Tailscale
network and services on the host's own ports. From v1.28.1, `block_private =
true` under `[network]` (or `--block-private`) keeps the public internet open and blocks private,
internal and link-local destinations. `allow_private = ["10.20.0.0/16"]` re-opens one range, such
as an internal registry. Cloud metadata stays blocked in every mode.

## Measured

On Linux x86_64 with v1.27.4, `node:22-bookworm-slim`: the first start, which runs `init`, took
27 s with the image already pulled and 191 s with a cold pull on top; a restart took under a
second with both agents still installed (OpenCode 1.19.0, Claude Code 2.1.300). A file the agent
wrote in `/workspace` appeared on the host owned by the host user, `git status` worked on the
mounted repo, `claude --dangerously-skip-permissions` was accepted as root, and `SSH_AUTH_SOCK`
was set in the guest.

On macOS arm64 with v1.29.0, the same Smolfile: the first start took 28 s with the image already
pulled and 51 s with a cold pull; a restart took under a second with both agents still installed
(OpenCode 1.19.1, Claude Code 2.1.301). A file written in `/workspace` appeared on the host, and
`git status` worked on the mounted repo.
