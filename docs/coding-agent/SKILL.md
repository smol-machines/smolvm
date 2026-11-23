---
name: coding-agent
description: Runs a coding agent (Claude Code, OpenCode, Codex, pi or any other) inside a persistent smolvm machine, so it can run with full permissions without touching the host, and with its API key kept outside the machine. Also covers running several attempts in parallel from one warm machine and keeping the best. Use when someone wants to sandbox their coding agent, run it in skip-permissions or YOLO mode safely, try a task several ways at once, or give it a disposable environment it can install anything into. Do not use it to run untrusted code with no network; use throwaway-machine for that.
---

# A coding agent in a machine

Verified on **smolvm v1.27.4** on Linux x86_64, 2026-10-14, on **v1.29.0** on macOS arm64,
2026-10-15, and on **v1.36.0** on macOS arm64, 2026-11-23 (both procedures). Done means the agent
runs inside the machine, the real API key never appears in it, and the agent's work reaches the
host repo.

## Procedure: one agent on your project

**1. Get the Smolfile into the project.** Edit the `npm install` line in `init` to the agents you
use; any install command works.

```bash
curl -fsSL https://raw.githubusercontent.com/smol-machines/smolvm/main/docs/coding-agent/assets/agent.smolfile -o Smolfile
```

**2. Create and start the machine, with the key kept outside.**

```bash
smolvm machine create --name agent -s Smolfile \
  --credential anthropic=ANTHROPIC_API_KEY@api.anthropic.com
smolvm machine start --name agent      # first start runs init: under a minute once the image is pulled
```

`--credential NAME=ENV_VAR@HOST` uses the **same variable name on both sides**: the real value is
read from the host's `ANTHROPIC_API_KEY`, and the guest's `ANTHROPIC_API_KEY` holds only a
placeholder that the host swaps for the real value on HTTPS requests to `api.anthropic.com`.
`create` prints one line per binding saying exactly that; check it names the variable your agent
reads. For OpenAI-based agents use `openai=OPENAI_API_KEY@api.openai.com`. `machine credentials
add` adds or changes a binding on a running machine without a restart.

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

## Procedure: several attempts in parallel, keep the best

The project is mounted from the host above, so the agent's edits live on your disk and a branch of
the machine would not carry them. To branch the work itself, keep the repo inside the machine.

**1. Create a source machine without the host mount** and start it as a branch source:

```bash
curl -fsSL https://raw.githubusercontent.com/smol-machines/smolvm/main/docs/coding-agent/assets/agent-branch.smolfile -o Smolfile
smolvm machine create --name agent-src -s Smolfile \
  --credential anthropic=ANTHROPIC_API_KEY@api.anthropic.com
smolvm machine start --name agent-src --branchable
```

**2. Put the repo in it.**

```bash
git bundle create /tmp/repo.bundle --all
smolvm machine cp /tmp/repo.bundle agent-src:/workspace/repo.bundle
smolvm machine exec --name agent-src -- sh -c 'cd /workspace && git clone -q repo.bundle proj'
```

Install dependencies and get the project to the state every attempt should start from, with `exec`
or an agent session in `/workspace/proj`.

**3. Branch it.** Each child is a full copy of the running machine: files, installed dependencies
and running processes.

```bash
smolvm machine branch --from agent-src --count 3 --name-prefix try --no-wait-ready
```

**4. Run one attempt per child**, for example a different prompt in each:

```bash
smolvm machine exec --name try-0 -it -- sh -c 'cd /workspace/proj && claude --dangerously-skip-permissions'
```

**5. Bring the best one back with git**, then delete the children:

```bash
smolvm machine exec --name try-1 -- sh -c 'cd /workspace/proj && git format-patch origin/HEAD..HEAD --stdout' | git am
for m in try-0 try-1 try-2; do smolvm machine delete --name "$m" -f; done
```

The agent must commit its work in the child for `format-patch` to carry it. The source keeps
running, so you can branch it again for the next task.

## Notes

- `init` runs once. Changing it later needs a new machine, or run the new commands with `exec`.
- Other agents install the same way: pi is `npm install -g @mariozechner/pi-coding-agent`.
- Subscription logins (Claude Pro/Max, ChatGPT plans) are not covered here; this procedure was
  verified with API keys.
- To keep the agent off your LAN and the host's ports, add `block_private = true` under
  `[network]` (from v1.28.1). See `README.md`.
- An agent that needs Docker: add `"/var/lib/docker", "/var/lib/containerd"` to `[dev] volumes`
  (from v1.28.1) and see [docker-in-machine](../docker-in-machine/README.md).
