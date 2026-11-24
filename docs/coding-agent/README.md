# A coding agent in a machine

Run Claude Code, OpenCode, Codex, pi or any other coding agent inside a machine, with full
permissions, so it can install packages, run anything and break things without touching your host.
The machine is the boundary, so the agent does not need to ask before each command, and its API key
stays on the host.

`SKILL.md` is the procedure. `assets/agent.smolfile` mounts your project; `assets/agent-branch.smolfile`
keeps the project inside the machine so you can branch it into parallel attempts. Nothing in smolvm
is specific to one agent: the Smolfile installs whichever ones you list, and the rest is ordinary
machine configuration.

## What the Smolfile sets up

| Need | How |
|---|---|
| The agent edits your project | `.:/workspace` mounts the directory holding the Smolfile; edits appear on the host immediately, owned by your host user |
| It can install and download | `net = true`; tighten with `[network] block_private = true` (see below) |
| Installs happen once | `init` runs on the first start only; later starts take about a second |
| git and ssh with your keys | `[auth] ssh_agent = true` forwards the host agent; keys never enter the machine |
| An API key the agent cannot read | `--credential anthropic=ANTHROPIC_API_KEY@api.anthropic.com` at create: the guest's `ANTHROPIC_API_KEY` holds a placeholder and the host substitutes the real value only on requests to that host ([credentials](../credentials/README.md)). `--secret-env` also works but puts the real value in the guest |

## Two things that fail without the Smolfile's fixes

**git refuses the mounted repo.** The agent runs as root in the machine and the repo belongs to
your host user, so git stops with `fatal: detected dubious ownership in repository at
'/workspace'`. The Smolfile's `git config --system --add safe.directory '*'` fixes it.

**Claude Code refuses its skip-permissions mode as root.** `claude
--dangerously-skip-permissions` prints `cannot be used with root/sudo privileges for security
reasons`. `IS_SANDBOX=1` in the machine's environment tells it it is in a sandbox, and the flag is
accepted.

## The credential flag names one variable, not two

`--credential NAME=ENV_VAR@HOST` reads the real value from the host's `ENV_VAR` and puts the
placeholder in the guest's `ENV_VAR`: the same name on both sides. Writing it as if it were
`GUEST_VAR=HOST_VAR` puts the placeholder in a variable the agent never reads, and the agent then
reports that it is not logged in. `machine create` and `machine credentials add` print one line per
binding naming the guest variable, so a wrong name shows up immediately.

## Parallel attempts

With the project mounted from the host, a branch of the machine shares nothing of the agent's
edits: they are on your disk. `agent-branch.smolfile` drops the mount; the repo is copied into
`/workspace`, the machine starts with `--branchable`, and `machine branch --count N` makes N full
copies of it, files, dependencies and running processes, each of which an agent works in
independently. The result comes back through git (`format-patch` in the child, `git am` on the
host), so review stays ordinary git.

## Many tasks instead of many worktrees

Running several agents at once usually means a git worktree per task, and each worktree installs and
builds its own dependencies. A machine with the repo and its build inside can be branched once per
task instead: the branches share the source's disk copy-on-write, so four branches of a machine
holding 1 GiB of build output added 4 MiB, against about 4 GiB for four worktrees. Each task runs
its agent headless in its own branch (`claude -p ...`), pushes its git branch through the forwarded
SSH agent, and the branch is deleted when the task is done. `SKILL.md` has the procedure.

## Use it from Claude Code

Install the skill once, so Claude Code knows the procedures:

```bash
mkdir -p ~/.claude/skills/coding-agent
curl -fsSL https://raw.githubusercontent.com/smol-machines/smolvm/main/docs/coding-agent/SKILL.md \
  -o ~/.claude/skills/coding-agent/SKILL.md
```

Then add a line like this to the project's `CLAUDE.md`, naming your source machine:

```markdown
For parallel tasks, do not create git worktrees. Use the coding-agent skill: run each task in its own
branch of the smolvm machine `myrepo-src`, push its git branch, then delete the branch.
```

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

On macOS arm64 with v1.36.0 (2026-11-23), `node:22-bookworm-slim`: the first start took 22 s with
the image already pulled, installing Claude Code 2.1.330 and OpenCode 1.19.6. With `--credential`,
the guest's variable held only a `SMOL_PLACEHOLDER_` value, the real value never appeared in the
guest, and Claude Code's requests reached Anthropic. From `agent-branch.smolfile`, `machine branch
--count 3` made three children in 2 s; each kept the work committed in the source, diverged on
its own, and the source was unchanged; the chosen child's commits applied on the host with `git am`. pi
0.73.1 installed with `npm install -g @mariozechner/pi-coding-agent`. Subscription logins were not
tested.

On macOS arm64 with v1.29.0, the same Smolfile: the first start took 28 s with the image already
pulled and 51 s with a cold pull; a restart took under a second with both agents still installed
(OpenCode 1.19.1, Claude Code 2.1.301). A file written in `/workspace` appeared on the host, and
`git status` worked on the mounted repo.
